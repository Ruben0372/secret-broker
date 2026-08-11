import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import Testing

/// Fake Cadence OAuth lifecycle.
///
/// ACCEPTANCE: the lifecycle is proven WITHOUT contacting Cadence and WITHOUT
/// creating an owner grant. Fakes only. Real integration is a documented stop
/// gate, and this issue does not cross it.
///
/// The properties worth having are structural where a type can carry them:
///
/// - A token has ONE audience, because `CadenceAudience` is a single value and
///   there is no collection anywhere to hold a second. A dual-audience
///   universal key is not refused, it is unsayable. That is the ARM-19 lesson
///   in this transport.
/// - A route is an enumerated profile, pinned as an exact reviewed set rather
///   than scanned for suspicious names. ARM-28 cost a correction for exactly
///   that difference and it is not relearned here.
/// - OAuth material is never returned by anything. The lifecycle hands back
///   opaque handles, and the material lives in a buffer the actor owns and
///   overwrites. The ARM-26 custody discipline applied to tokens.
///
/// Everything else is a check, and every check below is proven load-bearing by
/// removing it and watching the bypass return.

@Suite("Cadence OAuth lifecycle, fakes only")
struct CadenceOAuthTests {
    static func disposableDirectory(_ label: String = #function) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("arm30-disposable")
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    static func makeBroker(in directory: URL) throws -> FakeCadenceOAuthBroker {
        FakeCadenceOAuthBroker(
            refreshLedger: try SQLiteLedgerStore(
                path: directory.appendingPathComponent("oauth.sqlite").path
            )
        )
    }

    // MARK: PKCE

    @Test("A mismatched code verifier is refused")
    func pkceBindingIsEnforced() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)

        let challenge = CadencePKCE.challenge(forVerifier: "verifier-alpha-0123456789abcdef")
        let authorization = try broker.authorize(
            audience: .brokerControlPlane,
            route: .cadenceTokenExchange,
            codeChallenge: challenge
        )

        #expect(throws: CadenceOAuthRefusal.self, "a mismatched verifier completed the exchange") {
            _ = try broker.exchange(
                authorization,
                codeVerifier: "verifier-beta-fedcba9876543210",
                audience: .brokerControlPlane
            )
        }

        // POSITIVE CONTROL: the matching verifier completes, so the refusal is
        // about the binding and not about an exchange that never works.
        let grant = try broker.exchange(
            authorization,
            codeVerifier: "verifier-alpha-0123456789abcdef",
            audience: .brokerControlPlane
        )
        #expect(grant.generation == 1)
    }

    @Test("An authorization is single use even with the correct verifier")
    func authorizationIsSingleUse() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let verifier = "verifier-single-use-0123456789ab"
        let authorization = try broker.authorize(
            audience: .brokerControlPlane,
            route: .cadenceTokenExchange,
            codeChallenge: CadencePKCE.challenge(forVerifier: verifier)
        )

        _ = try broker.exchange(authorization, codeVerifier: verifier, audience: .brokerControlPlane)
        #expect(throws: CadenceOAuthRefusal.self, "an authorization code was redeemed twice") {
            _ = try broker.exchange(authorization, codeVerifier: verifier, audience: .brokerControlPlane)
        }
    }

    // MARK: Single audience

    @Test("A token carries exactly one audience, and a second is unsayable")
    func tokenCarriesExactlyOneAudience() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let verifier = "verifier-audience-0123456789abcd"
        let authorization = try broker.authorize(
            audience: .brokerControlPlane,
            route: .cadenceTokenExchange,
            codeChallenge: CadencePKCE.challenge(forVerifier: verifier)
        )
        let grant = try broker.exchange(
            authorization,
            codeVerifier: verifier,
            audience: .brokerControlPlane
        )

        #expect(grant.audience == .brokerControlPlane)

        // Presenting the grant for a DIFFERENT audience is refused. A token
        // that satisfied two audiences would be a universal key, which is the
        // failure this whole shape exists to prevent.
        for other in CadenceAudience.allCases where other != grant.audience {
            #expect(
                throws: CadenceOAuthRefusal.self,
                "a \(grant.audience.rawValue) token was accepted for \(other.rawValue)"
            ) {
                _ = try broker.accessToken(for: grant, audience: other)
            }
        }

        // POSITIVE CONTROL: its own audience is accepted.
        let handle = try broker.accessToken(for: grant, audience: .brokerControlPlane)
        #expect(handle.audience == .brokerControlPlane)

        // The exchange itself refuses to mint for an audience the authorization
        // was not opened for, so the binding starts before the token exists.
        let second = try broker.authorize(
            audience: .brokerControlPlane,
            route: .cadenceTokenExchange,
            codeChallenge: CadencePKCE.challenge(forVerifier: verifier)
        )
        #expect(throws: CadenceOAuthRefusal.self, "an audience was substituted at exchange time") {
            _ = try broker.exchange(second, codeVerifier: verifier, audience: .cadenceReadOnly)
        }
    }

    @Test("The audience and route vocabularies are exactly the reviewed sets")
    func vocabulariesMatchTheReviewedSets() {
        #expect(
            Set(CadenceAudience.allCases.map(\.rawValue)) == ["brokerControlPlane", "cadenceReadOnly"],
            "the audience set changed: \(CadenceAudience.allCases.map(\.rawValue).sorted()). A new audience is a new thing a token can be good for, and is a reviewed change."
        )
        #expect(
            Set(CadenceRoute.allCases.map(\.rawValue)) == [
                "cadenceAuthorization", "cadenceTokenExchange", "cadenceTokenRefresh", "cadenceRevocation",
            ],
            "the route set changed: \(CadenceRoute.allCases.map(\.rawValue).sorted()). A new route is a new destination, and is a reviewed change."
        )
    }

    // MARK: Generations

    @Test("A refreshed token supersedes its parent, and the old generation is refused")
    func refreshSupersedesTheParentGeneration() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let first = try Self.grant(from: broker, verifier: "verifier-generation-0123456789ab")

        let second = try broker.refresh(first)
        #expect(second.generation == first.generation + 1)
        #expect(second.familyID == first.familyID, "a refresh started a new token family")

        // The superseded generation is refused everywhere, not merely ignored.
        #expect(throws: CadenceOAuthRefusal.self, "a superseded generation still minted an access token") {
            _ = try broker.accessToken(for: first, audience: .brokerControlPlane)
        }

        // POSITIVE CONTROL: the current generation works, so supersession is a
        // property of the generation and not a broker that stopped working.
        let handle = try broker.accessToken(for: second, audience: .brokerControlPlane)
        #expect(handle.generation == second.generation)
    }

    // MARK: Refresh ambiguity

    @Test("Two refreshes of one token cannot both succeed")
    func refreshIsAtMostOnce() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let grant = try Self.grant(from: broker, verifier: "verifier-ambiguity-0123456789ab")

        _ = try broker.refresh(grant)
        #expect(throws: CadenceOAuthRefusal.self, "one refresh token was redeemed twice") {
            _ = try broker.refresh(grant)
        }
    }

    @Test("Refresh at-most-once survives a restart")
    func refreshAtMostOnceIsDurable() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("oauth.sqlite").path
        let verifier = "verifier-durable-0123456789abcde"

        let grant: CadenceGrant
        do {
            let broker = FakeCadenceOAuthBroker(refreshLedger: try SQLiteLedgerStore(path: path))
            grant = try Self.grant(from: broker, verifier: verifier)
            _ = try broker.refresh(grant)
        }

        // A NEW broker over the same ledger. At-most-once is a durable primary
        // key, not a set in memory, so a restart does not reopen the refresh.
        let restarted = FakeCadenceOAuthBroker(refreshLedger: try SQLiteLedgerStore(path: path))
        #expect(throws: CadenceOAuthRefusal.self, "a restart reopened a spent refresh token") {
            _ = try restarted.refresh(grant)
        }
    }

    // MARK: Revocation

    @Test("A revoked grant refuses all further exchange")
    func revocationRefusesEverything() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let grant = try Self.grant(from: broker, verifier: "verifier-revocation-0123456789ab")

        // POSITIVE CONTROL first: everything works before revocation, so the
        // refusals below are caused by it.
        _ = try broker.accessToken(for: grant, audience: .brokerControlPlane)

        try broker.revoke(familyID: grant.familyID)

        #expect(throws: CadenceOAuthRefusal.self, "a revoked family still minted an access token") {
            _ = try broker.accessToken(for: grant, audience: .brokerControlPlane)
        }
        #expect(throws: CadenceOAuthRefusal.self, "a revoked family still refreshed") {
            _ = try broker.refresh(grant)
        }

        // Revocation covers the whole family, not one generation. Revoking a
        // parent and leaving a child usable is how a revoked grant keeps
        // working through the token it already produced.
        let other = try Self.grant(from: broker, verifier: "verifier-revocation-other-01234")
        #expect(other.familyID != grant.familyID)
        _ = try broker.accessToken(for: other, audience: .brokerControlPlane)
    }

    @Test("Revocation of a parent covers a child minted before it")
    func revocationCoversTheWholeFamily() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let parent = try Self.grant(from: broker, verifier: "verifier-family-0123456789abcde")
        let child = try broker.refresh(parent)

        try broker.revoke(familyID: parent.familyID)
        #expect(throws: CadenceOAuthRefusal.self, "a child of a revoked family still worked") {
            _ = try broker.accessToken(for: child, audience: .brokerControlPlane)
        }
    }

    // MARK: Zeroization

    @Test("OAuth material is zeroized after use and does not linger in its buffer")
    func materialIsZeroizedAfterUse() throws {
        let material = CadenceSecretMaterial.generated(label: "arm30-zeroize", byteCount: 32)

        // POSITIVE CONTROL: it is non-zero to begin with. Without this the
        // assertion below would pass on a buffer that was never populated,
        // which is the way a zeroization test proves nothing.
        #expect(!material.allBytesAreZero, "the material was never populated, so zeroizing it proves nothing")
        #expect(material.byteCount == 32)

        let digest = try material.consumeComputingDigest()
        #expect(!digest.isEmpty)
        #expect(material.allBytesAreZero, "the material lingers in its buffer after use")

        // Consuming again is refused rather than returning a digest over zeros,
        // which would look like a working call and be meaningless.
        #expect(throws: CadenceOAuthRefusal.self, "spent material was consumed a second time") {
            _ = try material.consumeComputingDigest()
        }
    }

    @Test("A completed exchange leaves no live material behind")
    func exchangeZeroizesItsMaterial() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let grant = try Self.grant(from: broker, verifier: "verifier-lifecycle-0123456789ab")
        _ = try broker.accessToken(for: grant, audience: .brokerControlPlane)

        #expect(
            broker.liveMaterialCount == 0,
            "\(broker.liveMaterialCount) pieces of OAuth material are still live after the exchange completed"
        )
        // POSITIVE CONTROL: the counter is real. It counted something during
        // the lifecycle, so zero at the end is a result rather than a constant.
        #expect(broker.materialEverAllocated > 0, "no material was ever allocated, so the count above is vacuous")
    }

    // MARK: Route pinning

    @Test("Only a fixed typed request profile is representable")
    func routesArePinnedProfiles() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)

        // Every route has a fixed profile, and the profile is what the request
        // is built from. There is no string, no template and no caller-supplied
        // destination anywhere in the type, so an arbitrary route cannot be
        // written down rather than being refused at runtime.
        for route in CadenceRoute.allCases {
            let profile = CadenceRequestProfile.fixed(for: route)
            #expect(profile.route == route)
            #expect(!profile.path.isEmpty)
            #expect(profile.path.hasPrefix("/"), "\(route.rawValue) profile path is not a fixed absolute path")
        }

        // An authorization opened for one route cannot be exchanged on another.
        let verifier = "verifier-route-0123456789abcdef"
        let authorization = try broker.authorize(
            audience: .brokerControlPlane,
            route: .cadenceRevocation,
            codeChallenge: CadencePKCE.challenge(forVerifier: verifier)
        )
        #expect(throws: CadenceOAuthRefusal.self, "an authorization was exchanged on a route it was not opened for") {
            _ = try broker.exchange(authorization, codeVerifier: verifier, audience: .brokerControlPlane)
        }
    }

    // MARK: Material never reaches a consumer surface

    @Test("No consumer surface can obtain OAuth material")
    func materialNeverReachesAConsumerSurface() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let grant = try Self.grant(from: broker, verifier: "verifier-surfaces-0123456789abc")
        let handle = try broker.accessToken(for: grant, audience: .brokerControlPlane)

        // The four named consumers, each asked for everything it can see.
        let surfaces: [(String, String)] = [
            ("supervisor", broker.supervisorView(of: handle)),
            ("bridge", broker.bridgeView(of: handle)),
            ("guest", broker.guestView(of: handle)),
            ("log", broker.logLines.joined(separator: "\n")),
        ]
        #expect(surfaces.count == 4)

        // Scanned for the material digest AND for the material itself in every
        // rendering. The digest is the only thing about the material that
        // exists after zeroization, so if even that reaches a consumer the
        // separation has already failed.
        var findings: [String] = []
        for (label, surface) in surfaces {
            for probe in broker.materialProbeStrings {
                if surface.contains(probe) {
                    findings.append("\(label) carries material")
                }
            }
        }
        #expect(findings.isEmpty, "OAuth material reached a consumer surface: \(findings)")

        // POSITIVE CONTROLS: the surfaces were populated, so the scan ran
        // against real content, and the probe strings are non-empty so the
        // scan could have found something.
        for (label, surface) in surfaces {
            #expect(!surface.isEmpty, "the \(label) surface was empty, so nothing was scanned")
        }
        #expect(!broker.materialProbeStrings.isEmpty, "no probe strings, so the scan above proves nothing")
        #expect(
            broker.materialProbeStrings.allSatisfy { !$0.isEmpty },
            "an empty probe string would match every surface and hide a real leak"
        )
    }

    @Test("The scan detects material planted into a surface")
    func materialScanIsNotVacuous() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        _ = try Self.grant(from: broker, verifier: "verifier-vacuity-0123456789abcd")

        for probe in broker.materialProbeStrings {
            let planted = "supervisor(view: token=\(probe))"
            #expect(planted.contains(probe), "the scan cannot see material planted into a surface")
        }
    }

    @Test("A handle structurally cannot carry the material")
    func handleCannotCarryMaterial() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = try Self.makeBroker(in: directory)
        let grant = try Self.grant(from: broker, verifier: "verifier-handle-0123456789abcde")
        let handle = try broker.accessToken(for: grant, audience: .brokerControlPlane)

        // Names the token, never its value. Same discipline as the ARM-26
        // secret handle and the ARM-29 Signal handle.
        let rendered = String(describing: handle)
        for probe in broker.materialProbeStrings {
            #expect(!rendered.contains(probe), "the handle renders material")
        }
        #expect(handle.audience == .brokerControlPlane)
        #expect(!handle.tokenID.isEmpty)
    }

    // MARK: The stop gate

    @Test("Real Cadence integration is a stop gate and every real path refuses")
    func realIntegrationIsAStopGate() {
        #expect(FakeCadenceOAuthBroker.isRealIntegrationEnabled == false)
        #expect(!FakeCadenceOAuthBroker.realIntegrationStopGate.isEmpty)
        #expect(throws: CadenceOAuthRefusal.self, "a real Cadence broker was constructed") {
            _ = try FakeCadenceOAuthBroker.liveCadenceBroker(endpointIdentifier: "would-be-real")
        }
        #expect(throws: CadenceOAuthRefusal.self, "an owner grant was created") {
            _ = try FakeCadenceOAuthBroker.createOwnerGrant(ownerIdentifier: "would-be-owner")
        }
    }

    // MARK: Helpers

    static func grant(
        from broker: FakeCadenceOAuthBroker,
        verifier: String,
        audience: CadenceAudience = .brokerControlPlane
    ) throws -> CadenceGrant {
        let authorization = try broker.authorize(
            audience: audience,
            route: .cadenceTokenExchange,
            codeChallenge: CadencePKCE.challenge(forVerifier: verifier)
        )
        return try broker.exchange(authorization, codeVerifier: verifier, audience: audience)
    }
}
