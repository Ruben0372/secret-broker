import SecretBrokerCore
import SecretBrokerContracts
import SecretBrokerDaemon

/// A fabricated caller that satisfies the policy, so the ARM-5 behavioural
/// suites can keep testing what they were written to test now that every
/// daemon entry point is caller bound. The caller boundary itself is exercised
/// in SecretBrokerDaemonTests, not here.
enum TestCaller {
    static let policy = CallerPolicy(
        bundleIdentifier: "io.armel.fake.client",
        teamIdentifier: "FAKETEAM01",
        userIdentifier: 501,
        designatedRequirement: "identifier \"io.armel.fake.client\" and anchor apple generic",
        permittedOperations: Set(BrokeredOperationKind.allCases)
    )

    static let verifier = PolicyCallerVerifier(policy: policy)

    static let identity = CallerIdentity(
        bundleIdentifier: policy.bundleIdentifier,
        teamIdentifier: policy.teamIdentifier,
        userIdentifier: policy.userIdentifier,
        designatedRequirement: policy.designatedRequirement,
        auditToken: AuditToken(opaqueValue: 0x0000_0000_000A_11CE),
        isDebugIdentity: false
    )
}

extension DaemonOutcome {
    /// Receipt for a completed call, nil for a denial. Tests that expect a
    /// receipt use #require so a denial fails loudly instead of unwrapping.
    var receipt: BrokeredReceipt? {
        if case .completed(let receipt) = self {
            return receipt
        }
        return nil
    }
}
