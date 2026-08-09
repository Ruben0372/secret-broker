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
/// 4. Artifact assertions over the compiled modules' undefined symbols: a
///    reviewed golden allowlist that notices anything new, and a denylist that
///    names known-bad families with a readable failure. These catch a
///    capability regardless of how its source is spelled.
/// 5. The forbidden-token scan over sources, a best-effort review aid only. It
///    matches text, ordinary Swift can evade it, and it is not a control.
///
/// Honest limits of layer 4: the check is macOS and Objective-C interop
/// specific. The stable signal is the _OBJC_CLASS_$_ class reference that
/// appears when a module touches a Foundation class; selector stubs are not the
/// primary signal and are not relied on. The residual limit is capability
/// reachable through APIs the module already legitimately links, which by
/// definition introduces no new symbol. These layers raise the cost of an
/// obfuscated capability and narrow what can be added unnoticed. They do not
/// make the boundary airtight.
public enum RuntimeCapability: String, CaseIterable, Sendable, Codable {
    case availabilityCheck
}

public enum RuntimePolicy {
    public static let capabilities: Set<RuntimeCapability> = [.availabilityCheck]
}

public enum SecretBrokerVersion {
    public static let current = "1.0.1"
}
