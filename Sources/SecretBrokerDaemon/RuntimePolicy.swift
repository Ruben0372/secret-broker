/// Capability surface of the daemon runtime.
///
/// The declared capabilities are availability checking only. Adding another
/// capability requires a case here and security review.
///
/// What enforces that boundary: the daemon dependency allowlist, the adapters
/// target being unexported, and the seam and API pinning tests that fix the
/// custody protocol method set, the request case list, and the public daemon
/// return types. The forbidden-token scan over sources is a best-effort review
/// aid on top of those: it matches text, so ordinary Swift can evade it, and it
/// should not be read as a control.
public enum RuntimeCapability: String, CaseIterable, Sendable, Codable {
    case availabilityCheck
}

public enum RuntimePolicy {
    public static let capabilities: Set<RuntimeCapability> = [.availabilityCheck]
}

public enum SecretBrokerVersion {
    public static let current = "1.0.1"
}
