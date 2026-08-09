/// Capability surface of the daemon runtime.
///
/// The declared capabilities are availability checking only. Adding another
/// capability requires a case here and security review.
///
/// Layered enforcement of that boundary:
/// 1. The daemon dependency allowlist, pinned by test.
/// 2. Products that do not export the adapters target, pinned by test.
/// 3. Seam and public API pinning: the exact custody method set, the exact
///    request case list, and the exact public daemon methods and return types.
/// 4. An artifact assertion over the compiled daemon module's undefined
///    symbols, which catches a capability regardless of how its source is
///    spelled and so does not lose to obfuscation the way text matching does.
/// 5. The forbidden-token scan over sources, a best-effort review aid only. It
///    matches text, ordinary Swift can evade it, and it is not a control.
///
/// Residual limit: layer 4 is a denylist of named symbol families. A capability
/// reached through an already-linked Foundation surface, ProcessInfo
/// environment access being the clearest example, resolves inside Foundation
/// and never appears in the daemon's undefined symbols. These layers raise the
/// cost of an obfuscated capability. They do not make the boundary airtight,
/// and it should not be described as if they do.
public enum RuntimeCapability: String, CaseIterable, Sendable, Codable {
    case availabilityCheck
}

public enum RuntimePolicy {
    public static let capabilities: Set<RuntimeCapability> = [.availabilityCheck]
}

public enum SecretBrokerVersion {
    public static let current = "1.0.1"
}
