/// Capability surface of the daemon runtime.
///
/// Deliberate constraint: there is no environment export, process execution,
/// or bulk read capability, and none can be expressed without adding a case
/// here. Additions require security review; the bootstrap tests pin both the
/// capability list and the absence of export-capable tokens in sources.
public enum RuntimeCapability: String, CaseIterable, Sendable, Codable {
    case availabilityCheck
}

public enum RuntimePolicy {
    public static let capabilities: Set<RuntimeCapability> = [.availabilityCheck]
}

public enum SecretBrokerVersion {
    public static let current = "1.0.1"
}
