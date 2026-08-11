import CryptoKit
import Foundation

/// Vocabulary for the fake Cadence OAuth lifecycle.
///
/// Two properties are carried by the types rather than by checks, which is the
/// difference between a guarantee and a habit:
///
/// SINGLE AUDIENCE. `CadenceGrant.audience` is one `CadenceAudience`. There is
/// no set, no array and no wildcard anywhere in this file, so a token good for
/// two audiences cannot be constructed. A dual-audience universal key is not
/// refused; it is unsayable. That is the ARM-19 lesson expressed in the type
/// rather than enforced at every call site that might forget.
///
/// FIXED ROUTES. A route is an enumerated case with a fixed profile. There is
/// no string, no URL and no template, so a caller cannot supply a destination
/// and a new destination is a reviewed code change.

public enum CadenceAudience: String, Sendable, Hashable, CaseIterable, Codable {
    case brokerControlPlane
    case cadenceReadOnly
}

public enum CadenceRoute: String, Sendable, Hashable, CaseIterable, Codable {
    case cadenceAuthorization
    case cadenceTokenExchange
    case cadenceTokenRefresh
    case cadenceRevocation
}

/// The fixed request profile for a route.
///
/// Every field is derived from the route through an exhaustive switch, so a new
/// route fails to compile until someone writes its profile. There is deliberately
/// no initialiser taking a caller-supplied path: the only way to obtain a
/// profile is to name a route that already exists.
public struct CadenceRequestProfile: Sendable, Hashable {
    public let route: CadenceRoute
    public let path: String
    public let method: String

    public static func fixed(for route: CadenceRoute) -> CadenceRequestProfile {
        switch route {
        case .cadenceAuthorization:
            return CadenceRequestProfile(route: route, path: "/oauth/authorize", method: "POST")
        case .cadenceTokenExchange:
            return CadenceRequestProfile(route: route, path: "/oauth/token", method: "POST")
        case .cadenceTokenRefresh:
            return CadenceRequestProfile(route: route, path: "/oauth/token/refresh", method: "POST")
        case .cadenceRevocation:
            return CadenceRequestProfile(route: route, path: "/oauth/revoke", method: "POST")
        }
    }
}

public enum CadenceOAuthRefusal: String, Error, Sendable, Hashable, CaseIterable {
    case codeVerifierMismatch
    case authorizationAlreadyRedeemed
    case authorizationUnknown
    case audienceMismatch
    case routeMismatch
    case supersededGeneration
    case refreshAlreadyRedeemed
    case grantRevoked
    case materialAlreadyConsumed
    case realIntegrationDisabled
    case ownerGrantCreationDisabled
}

// MARK: PKCE

public enum CadencePKCE {
    /// S256: the challenge is a digest of the verifier, so holding the
    /// challenge does not let anyone produce the verifier. The exchange
    /// recomputes and compares, which is what binds the redemption to whoever
    /// started the authorization.
    public static func challenge(forVerifier verifier: String) -> String {
        SHA256.hash(data: Data(verifier.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: Material

/// OAuth material, in a buffer this type owns so it can be overwritten.
///
/// Nothing here returns the bytes. The only operations are "use it once and
/// zeroize" and "tell me whether the buffer is now zero", so a caller cannot
/// obtain the material even by accident, and a test can still prove the
/// zeroization happened.
///
/// HONEST LIMIT, and it matters. This zeroizes the buffer THIS TYPE OWNS. It
/// cannot prove the bytes are absent from the whole process: Swift may keep
/// copies in temporaries, and freed pages are not scrubbed by the allocator.
/// The material is generated directly into the buffer rather than passed in as
/// an array, which removes the most obvious extra copy, and that is the extent
/// of the claim. Saying more than that would assert a boundary that is not
/// there.
public final class CadenceSecretMaterial: @unchecked Sendable {
    private let storage: UnsafeMutableBufferPointer<UInt8>
    private let lock = NSLock()
    private var isConsumed = false

    public let byteCount: Int
    /// Digest of the material, taken once at generation. This is what a test
    /// searches consumer surfaces for: after zeroization it is the only thing
    /// about the material that still exists, so if even this reaches a
    /// consumer, separation has already failed.
    public let probeDigest: String

    private init(storage: UnsafeMutableBufferPointer<UInt8>, probeDigest: String) {
        self.storage = storage
        self.byteCount = storage.count
        self.probeDigest = probeDigest
    }

    /// Generates directly into the owned buffer. Deterministic, because this is
    /// a fake and a test needs to be able to run it twice; a real
    /// implementation would draw from the system CSPRNG and this comment is
    /// where that difference is recorded rather than assumed.
    public static func generated(label: String, byteCount: Int) -> CadenceSecretMaterial {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: byteCount)
        var seed = Array(SHA256.hash(data: Data("arm30.fake.material.\(label)".utf8)))
        var index = 0
        while index < byteCount {
            if index % seed.count == 0, index > 0 {
                seed = Array(SHA256.hash(data: Data(seed)))
            }
            buffer[index] = seed[index % seed.count]
            index += 1
        }
        let digest = SHA256.hash(data: Data(buffer)).map { String(format: "%02x", $0) }.joined()
        return CadenceSecretMaterial(storage: buffer, probeDigest: digest)
    }

    public var allBytesAreZero: Bool {
        lock.lock(); defer { lock.unlock() }
        return storage.allSatisfy { $0 == 0 }
    }

    /// Uses the material exactly once, then overwrites it.
    ///
    /// Refusing a second use matters more than it looks: after zeroization a
    /// second call would digest a buffer of zeros and return something that
    /// looks like a working answer. A refusal says the material is gone; a
    /// digest over zeros pretends it is still there.
    @discardableResult
    public func consumeComputingDigest() throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard !isConsumed else { throw CadenceOAuthRefusal.materialAlreadyConsumed }
        let digest = SHA256.hash(data: Data(storage)).map { String(format: "%02x", $0) }.joined()
        for index in storage.indices { storage[index] = 0 }
        isConsumed = true
        return digest
    }

    deinit {
        for index in storage.indices { storage[index] = 0 }
        storage.deallocate()
    }
}

// MARK: Grants and handles

/// A token family membership. Carries identity and generation, never material.
public struct CadenceGrant: Sendable, Hashable, CustomStringConvertible {
    public let familyID: String
    public let generation: UInt64
    public let audience: CadenceAudience
    public let refreshTokenID: String

    public var description: String {
        "CadenceGrant(\(familyID)#\(generation) for \(audience.rawValue))"
    }
}

/// Opaque reference to a minted access token.
///
/// Structurally cannot carry the token: there is no field that could hold it.
/// The ARM-26 discipline applied to OAuth material.
public struct CadenceAccessTokenHandle: Sendable, Hashable, CustomStringConvertible {
    public let tokenID: String
    public let familyID: String
    public let generation: UInt64
    public let audience: CadenceAudience

    public var description: String {
        // Names the token and what it is good for. Never its value.
        "CadenceAccessTokenHandle(\(tokenID) family \(familyID)#\(generation) for \(audience.rawValue))"
    }
}

/// An opened authorization, waiting to be redeemed exactly once.
public struct CadenceAuthorization: Sendable, Hashable {
    public let authorizationID: String
    public let audience: CadenceAudience
    public let route: CadenceRoute
    public let codeChallenge: String
}
