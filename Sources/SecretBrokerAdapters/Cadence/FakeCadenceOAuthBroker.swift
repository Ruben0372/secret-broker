import CryptoKit
import Foundation
import SecretBrokerContracts

/// Fake Cadence OAuth broker.
///
/// Proves the lifecycle without contacting Cadence and without creating an
/// owner grant. Authorization, exchange, refresh, revocation and access-token
/// minting all run against in-process state and a local ledger file. Nothing
/// here opens a socket.
///
/// # Real integration stop gate
///
/// Real Cadence integration is NOT crossed in Wave 1, and the gate is code
/// rather than a note. `isRealIntegrationEnabled` is false, and both real
/// entry points refuse while it is.
///
/// Crossing the gate requires, and none of these exist yet:
///
/// 1. A reviewed Cadence client registration with its redirect profile pinned,
///    so the authorization route cannot be pointed elsewhere.
/// 2. An owner grant created by the OWNER through Cadence's own flow. This
///    broker must never mint one, which is why `createOwnerGrant` refuses
///    unconditionally rather than being gated on the same flag: a flag someone
///    can flip is the wrong shape for "the broker is not the owner".
/// 3. Transport material drawn from the system CSPRNG rather than the
///    deterministic generator used here, which exists so tests can repeat.
/// 4. A decision on where refresh material rests between uses, which is a
///    custody question and belongs with the ARM-26 boundary.
///
/// Until all four land, the fake is the only path that works.
public final class FakeCadenceOAuthBroker: @unchecked Sendable {
    public static let isRealIntegrationEnabled = false

    public static let realIntegrationStopGate = """
    Real Cadence integration stays disabled until a reviewed client \
    registration, an owner-created grant, CSPRNG transport material and a \
    custody decision for resting refresh material all exist. Wave 1 proves the \
    lifecycle against a fake; it does not contact Cadence and does not create \
    an owner grant.
    """

    private let refreshLedger: any LedgerStore
    private let lock = NSLock()

    private var authorizations: [String: CadenceAuthorization] = [:]
    private var redeemedAuthorizations: Set<String> = []
    private var currentGeneration: [String: UInt64] = [:]
    private var familyAudience: [String: CadenceAudience] = [:]
    private var revokedFamilies: Set<String> = []
    private var probeDigests: [String] = []
    private var liveMaterial = 0
    private var allocatedMaterial = 0
    private var log: [String] = []
    private var counter: UInt64 = 0

    public init(refreshLedger: any LedgerStore) {
        self.refreshLedger = refreshLedger
    }

    // MARK: Stop gate

    public static func liveCadenceBroker(endpointIdentifier: String) throws -> FakeCadenceOAuthBroker {
        guard isRealIntegrationEnabled else {
            throw CadenceOAuthRefusal.realIntegrationDisabled
        }
        throw CadenceOAuthRefusal.realIntegrationDisabled
    }

    /// Refuses unconditionally, and deliberately not behind
    /// `isRealIntegrationEnabled`. An owner grant is created by the owner, and
    /// a flag this code can flip is the wrong shape for that boundary: it would
    /// say the broker may mint one once somebody decides it may.
    public static func createOwnerGrant(ownerIdentifier: String) throws -> CadenceGrant {
        throw CadenceOAuthRefusal.ownerGrantCreationDisabled
    }

    // MARK: Lifecycle

    public func authorize(
        audience: CadenceAudience,
        route: CadenceRoute,
        codeChallenge: String
    ) throws -> CadenceAuthorization {
        lock.lock(); defer { lock.unlock() }
        counter += 1
        let authorization = CadenceAuthorization(
            authorizationID: "auth-\(counter)",
            audience: audience,
            route: route,
            codeChallenge: codeChallenge
        )
        authorizations[authorization.authorizationID] = authorization
        log.append("cadence: opened \(authorization.authorizationID) for \(audience.rawValue) on \(route.rawValue)")
        return authorization
    }

    public func exchange(
        _ authorization: CadenceAuthorization,
        codeVerifier: String,
        audience: CadenceAudience
    ) throws -> CadenceGrant {
        lock.lock(); defer { lock.unlock() }
        guard authorizations[authorization.authorizationID] != nil else {
            throw CadenceOAuthRefusal.authorizationUnknown
        }
        // Single use, checked before the verifier so a replayed code is refused
        // as a replay rather than as a bad verifier. The reason a caller sees
        // should name what actually went wrong.
        guard !redeemedAuthorizations.contains(authorization.authorizationID) else {
            throw CadenceOAuthRefusal.authorizationAlreadyRedeemed
        }
        guard authorization.route == .cadenceTokenExchange else {
            throw CadenceOAuthRefusal.routeMismatch
        }
        guard authorization.audience == audience else {
            // The audience is fixed when the authorization is opened, so it
            // cannot be substituted at redemption time.
            throw CadenceOAuthRefusal.audienceMismatch
        }
        guard CadencePKCE.challenge(forVerifier: codeVerifier) == authorization.codeChallenge else {
            throw CadenceOAuthRefusal.codeVerifierMismatch
        }

        redeemedAuthorizations.insert(authorization.authorizationID)
        counter += 1
        let familyID = "family-\(counter)"
        currentGeneration[familyID] = 1
        familyAudience[familyID] = audience
        mintAndZeroizeMaterial(label: "exchange-\(familyID)-1")
        log.append("cadence: exchanged \(authorization.authorizationID) into \(familyID) generation 1")
        return CadenceGrant(
            familyID: familyID,
            generation: 1,
            audience: audience,
            refreshTokenID: "refresh-\(familyID)-1"
        )
    }

    public func refresh(_ grant: CadenceGrant) throws -> CadenceGrant {
        lock.lock(); defer { lock.unlock() }
        try requireUsable(grant)

        // At-most-once, durable. The refresh token id is a primary key in the
        // same store the ledger uses, so two refreshes of one token cannot both
        // succeed and a restart does not reopen a spent one. A set in memory
        // would lose exactly the case that matters.
        let identifier = try LedgerOperationID("cadence.refresh.\(grant.refreshTokenID)")
        let row = try LedgerRow(
            operationID: identifier,
            digest: LedgerDigest.over(Array(grant.refreshTokenID.utf8)),
            state: .settledSucceeded,
            sequence: 1
        )
        guard try refreshLedger.createIfAbsent(row).created else {
            throw CadenceOAuthRefusal.refreshAlreadyRedeemed
        }

        let next = grant.generation + 1
        currentGeneration[grant.familyID] = next
        mintAndZeroizeMaterial(label: "refresh-\(grant.familyID)-\(next)")
        log.append("cadence: refreshed \(grant.familyID) to generation \(next)")
        return CadenceGrant(
            familyID: grant.familyID,
            generation: next,
            audience: grant.audience,
            refreshTokenID: "refresh-\(grant.familyID)-\(next)"
        )
    }

    public func accessToken(
        for grant: CadenceGrant,
        audience: CadenceAudience
    ) throws -> CadenceAccessTokenHandle {
        lock.lock(); defer { lock.unlock() }
        try requireUsable(grant)
        guard grant.audience == audience, familyAudience[grant.familyID] == audience else {
            // One audience per token. Presenting it for another is refused, and
            // there is no shape in which it could satisfy both.
            throw CadenceOAuthRefusal.audienceMismatch
        }
        mintAndZeroizeMaterial(label: "access-\(grant.familyID)-\(grant.generation)")
        counter += 1
        log.append("cadence: minted access token for \(grant.familyID)#\(grant.generation)")
        return CadenceAccessTokenHandle(
            tokenID: "token-\(counter)",
            familyID: grant.familyID,
            generation: grant.generation,
            audience: audience
        )
    }

    public func revoke(familyID: String) throws {
        lock.lock(); defer { lock.unlock() }
        // Whole family, not one generation. Revoking a parent and leaving a
        // child usable is how a revoked grant keeps working through the token
        // it already produced.
        revokedFamilies.insert(familyID)
        log.append("cadence: revoked family \(familyID)")
    }

    /// Revocation first, then generation. A revoked family must not report a
    /// superseded generation instead: the caller needs to know the grant is
    /// gone, not that it is merely old.
    private func requireUsable(_ grant: CadenceGrant) throws {
        guard !revokedFamilies.contains(grant.familyID) else {
            throw CadenceOAuthRefusal.grantRevoked
        }
        guard currentGeneration[grant.familyID] == grant.generation else {
            throw CadenceOAuthRefusal.supersededGeneration
        }
    }

    /// Material exists only for the duration of the step that needs it.
    ///
    /// Generated, used, zeroized, released. Nothing retains it and nothing
    /// returns it, so there is no live material between calls and no accessor
    /// through which a consumer could ask for one.
    private func mintAndZeroizeMaterial(label: String) {
        let material = CadenceSecretMaterial.generated(label: label, byteCount: 32)
        allocatedMaterial += 1
        liveMaterial += 1
        probeDigests.append(material.probeDigest)
        _ = try? material.consumeComputingDigest()
        liveMaterial -= 1
    }

    // MARK: Consumer surfaces

    /// What the Supervisor can see. Identity and audience, never material.
    public func supervisorView(of handle: CadenceAccessTokenHandle) -> String {
        "supervisor(token: \(handle.tokenID), family: \(handle.familyID), generation: \(handle.generation), audience: \(handle.audience.rawValue))"
    }

    /// What the Bridge can see. Less than the Supervisor: it needs to know a
    /// token exists and what it is good for, not which family it came from.
    public func bridgeView(of handle: CadenceAccessTokenHandle) -> String {
        "bridge(token: \(handle.tokenID), audience: \(handle.audience.rawValue))"
    }

    /// What a guest can see. The least of all: that a token exists, and nothing
    /// else. A guest has no reason to learn an audience.
    public func guestView(of handle: CadenceAccessTokenHandle) -> String {
        "guest(token: \(handle.tokenID))"
    }

    public var logLines: [String] {
        lock.lock(); defer { lock.unlock() }
        return log
    }

    /// Digests of every piece of material this broker has ever minted, for a
    /// test to search consumer surfaces for. Exposed deliberately and only
    /// here: it is the strongest thing that still exists after zeroization, so
    /// a surface that does not contain it does not contain anything weaker.
    public var materialProbeStrings: [String] {
        lock.lock(); defer { lock.unlock() }
        return probeDigests
    }

    public var liveMaterialCount: Int {
        lock.lock(); defer { lock.unlock() }
        return liveMaterial
    }

    public var materialEverAllocated: Int {
        lock.lock(); defer { lock.unlock() }
        return allocatedMaterial
    }
}
