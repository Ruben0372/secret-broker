/// Why a caller was refused. Distinct cases on purpose: a single generic
/// denial would let a widened check hide behind an unchanged refusal.
public enum CallerDenial: String, Sendable, Hashable, Codable {
    case missingAuditToken
    case debugIdentity
    case bundleMismatch
    case teamMismatch
    case userMismatch
    case designatedRequirementMismatch
    case operationNotPermitted
    case productionVerificationUnavailable
}

public enum CallerVerification: Sendable, Hashable {
    case allowed
    case denied(CallerDenial)
}

/// Injectable caller check. Injectable so tests exercise the boundary with
/// fakes and so the production implementation can be swapped in once a release
/// identity exists, without the dispatch path changing shape.
public protocol CallerVerifier: Sendable {
    func verify(_ caller: CallerIdentity, for operation: BrokeredOperationKind) async -> CallerVerification
}

/// Verifier that checks a caller against a fixed policy.
///
/// Order matters and is deliberate: the token and build-type gates run before
/// any identity comparison, so an unverifiable caller is refused for being
/// unverifiable rather than for happening to mismatch a field.
public struct PolicyCallerVerifier: CallerVerifier {
    public let policy: CallerPolicy

    public init(policy: CallerPolicy) {
        self.policy = policy
    }

    public func verify(
        _ caller: CallerIdentity,
        for operation: BrokeredOperationKind
    ) async -> CallerVerification {
        guard caller.auditToken != nil else {
            return .denied(.missingAuditToken)
        }
        guard !caller.isDebugIdentity else {
            return .denied(.debugIdentity)
        }
        guard caller.bundleIdentifier == policy.bundleIdentifier else {
            return .denied(.bundleMismatch)
        }
        guard caller.teamIdentifier == policy.teamIdentifier else {
            return .denied(.teamMismatch)
        }
        guard caller.userIdentifier == policy.userIdentifier else {
            return .denied(.userMismatch)
        }
        guard caller.designatedRequirement == policy.designatedRequirement else {
            return .denied(.designatedRequirementMismatch)
        }
        guard policy.permittedOperations.contains(operation) else {
            return .denied(.operationNotPermitted)
        }
        return .allowed
    }
}

/// The verifier the daemon uses outside tests.
///
/// Production audit-token verification is not implemented, because deciding
/// that a token belongs to a trusted caller requires a release signing identity
/// this package does not yet have. Rather than approximate that check, this
/// verifier refuses every call. The boundary is therefore closed by default,
/// and turning it on is a deliberate act that must arrive with the identity.
public struct ProductionCallerVerifier: CallerVerifier {
    /// Flipped only when real audit-token verification lands.
    public static let isAuditTokenVerificationEnabled = false

    public static let releaseIdentityGate = """
    Release identity gate: production caller verification stays disabled until a \
    Developer ID release signing identity is provisioned and the daemon can \
    verify a caller's audit token against its designated requirement. While it \
    is disabled this verifier denies every call, including well-formed ones. \
    Do not substitute a weaker check to unblock work: an approximate caller \
    check is worse than a closed door, because it looks like a boundary.
    """

    public init() {}

    public func verify(
        _ caller: CallerIdentity,
        for operation: BrokeredOperationKind
    ) async -> CallerVerification {
        .denied(.productionVerificationUnavailable)
    }
}
