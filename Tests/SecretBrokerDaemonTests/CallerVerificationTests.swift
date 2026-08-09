import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// Caller boundary tests. Every identity here is a fake: no real audit token,
/// no real code signature, no Keychain, no production credential. The point is
/// that each denial reason is distinguishable, so a future change that widens
/// one dimension cannot hide behind a generic refusal.
@Suite("Caller verification boundary")
struct CallerVerificationTests {
    /// The policy a verified caller must satisfy. Values are fabricated.
    static let policy = CallerPolicy(
        bundleIdentifier: "io.armel.fake.client",
        teamIdentifier: "FAKETEAM01",
        userIdentifier: 501,
        designatedRequirement: "identifier \"io.armel.fake.client\" and anchor apple generic",
        permittedOperations: [.availability]
    )

    /// A caller that satisfies every dimension. Individual tests break exactly
    /// one thing, so the reported denial is unambiguous.
    static func validCaller() -> CallerIdentity {
        CallerIdentity(
            bundleIdentifier: policy.bundleIdentifier,
            teamIdentifier: policy.teamIdentifier,
            userIdentifier: policy.userIdentifier,
            designatedRequirement: policy.designatedRequirement,
            auditToken: FakeAuditToken.valid,
            isDebugIdentity: false
        )
    }

    static func verifier() -> PolicyCallerVerifier {
        PolicyCallerVerifier(policy: policy)
    }

    @Test("A valid fake designated requirement is accepted")
    func validCallerAccepted() async {
        let decision = await Self.verifier().verify(Self.validCaller(), for: .availability)
        #expect(decision == .allowed)
    }

    @Test("A caller from the wrong bundle is denied for that reason")
    func wrongBundleDenied() async {
        var caller = Self.validCaller()
        caller.bundleIdentifier = "io.attacker.other"
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.bundleMismatch))
    }

    @Test("A caller from the wrong team is denied for that reason")
    func wrongTeamDenied() async {
        var caller = Self.validCaller()
        caller.teamIdentifier = "OTHERTEAM9"
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.teamMismatch))
    }

    @Test("A caller running as another user is denied for that reason")
    func wrongUserDenied() async {
        var caller = Self.validCaller()
        caller.userIdentifier = 502
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.userMismatch))
    }

    @Test("A caller requesting an operation outside its grant is denied")
    func wrongOperationDenied() async {
        let narrowed = CallerPolicy(
            bundleIdentifier: Self.policy.bundleIdentifier,
            teamIdentifier: Self.policy.teamIdentifier,
            userIdentifier: Self.policy.userIdentifier,
            designatedRequirement: Self.policy.designatedRequirement,
            permittedOperations: []
        )
        let decision = await PolicyCallerVerifier(policy: narrowed)
            .verify(Self.validCaller(), for: .availability)
        #expect(decision == .denied(.operationNotPermitted))
    }

    @Test("A debug identity is denied even when everything else matches")
    func debugIdentityDenied() async {
        var caller = Self.validCaller()
        caller.isDebugIdentity = true
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.debugIdentity))
    }

    @Test("A missing audit token is denied and never treated as absent-but-fine")
    func missingAuditTokenDenied() async {
        var caller = Self.validCaller()
        caller.auditToken = nil
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.missingAuditToken))
    }

    @Test("A mismatched designated requirement is denied for that reason")
    func designatedRequirementMismatchDenied() async {
        var caller = Self.validCaller()
        caller.designatedRequirement = "identifier \"io.attacker.other\" and anchor apple generic"
        let decision = await Self.verifier().verify(caller, for: .availability)
        #expect(decision == .denied(.designatedRequirementMismatch))
    }

    @Test("Every denial reason the enum declares is reachable and distinct")
    func denialReasonsAreDistinct() async {
        var reasons: Set<CallerDenial> = []
        func record(_ verification: CallerVerification) {
            if case .denied(let reason) = verification {
                reasons.insert(reason)
            }
        }

        var wrongBundle = Self.validCaller()
        wrongBundle.bundleIdentifier = "io.attacker.other"
        var wrongTeam = Self.validCaller()
        wrongTeam.teamIdentifier = "OTHERTEAM9"
        var wrongUser = Self.validCaller()
        wrongUser.userIdentifier = 502
        var debugCaller = Self.validCaller()
        debugCaller.isDebugIdentity = true
        var noToken = Self.validCaller()
        noToken.auditToken = nil
        var wrongRequirement = Self.validCaller()
        wrongRequirement.designatedRequirement = "identifier \"io.attacker.other\""

        for caller in [wrongBundle, wrongTeam, wrongUser, debugCaller, noToken, wrongRequirement] {
            record(await Self.verifier().verify(caller, for: .availability))
        }

        let narrowed = CallerPolicy(
            bundleIdentifier: Self.policy.bundleIdentifier,
            teamIdentifier: Self.policy.teamIdentifier,
            userIdentifier: Self.policy.userIdentifier,
            designatedRequirement: Self.policy.designatedRequirement,
            permittedOperations: []
        )
        record(await PolicyCallerVerifier(policy: narrowed).verify(Self.validCaller(), for: .availability))
        record(await ProductionCallerVerifier().verify(Self.validCaller(), for: .availability))

        #expect(reasons.count == 8, "denial reasons collapsed: \(reasons)")
        // Completeness against the enum itself: a reason added later that no
        // test can produce fails here rather than shipping unexercised.
        let declared = Set(CallerDenial.allCases)
        #expect(
            declared == reasons,
            "denial reasons not reached by any case: \(declared.subtracting(reasons))"
        )
    }
}

/// Production mode holds the acceptance criterion: until a release signing
/// identity exists, audit-token verification cannot be performed, so the
/// verifier refuses everything rather than assuming the caller is fine.
@Suite("Production verifier fails closed")
struct ProductionVerifierTests {
    @Test("Production rejects even a fully valid caller")
    func rejectsValidCaller() async {
        let decision = await ProductionCallerVerifier()
            .verify(CallerVerificationTests.validCaller(), for: .availability)
        #expect(decision == .denied(.productionVerificationUnavailable))
    }

    @Test("Production rejects every operation kind")
    func rejectsEveryOperation() async {
        for operation in BrokeredOperationKind.allCases {
            let decision = await ProductionCallerVerifier()
                .verify(CallerVerificationTests.validCaller(), for: operation)
            #expect(decision == .denied(.productionVerificationUnavailable))
        }
    }

    @Test("Production verification is explicitly disabled pending release identity")
    func statesWhyItRefuses() {
        #expect(ProductionCallerVerifier.isAuditTokenVerificationEnabled == false)
        #expect(ProductionCallerVerifier.releaseIdentityGate.contains("release signing identity"))
    }
}
