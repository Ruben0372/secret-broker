import SecretBrokerContracts

/// Opaque handle for a kernel audit token.
///
/// The daemon never inspects this value here. Its presence or absence is the
/// only thing the foundations act on, because deriving a caller's identity from
/// an audit token requires the release-identity work that is not done yet. A
/// missing token is a denial, never a shrug.
public struct AuditToken: Sendable, Hashable {
    public let opaqueValue: UInt64

    public init(opaqueValue: UInt64) {
        self.opaqueValue = opaqueValue
    }
}

/// What the daemon believes about a caller. Every field is a separate denial
/// dimension, so a refusal names the dimension that failed instead of
/// collapsing to a single boolean that hides which check did the work.
public struct CallerIdentity: Sendable, Hashable {
    public var bundleIdentifier: String
    public var teamIdentifier: String
    public var userIdentifier: UInt32
    public var designatedRequirement: String
    public var auditToken: AuditToken?
    public var isDebugIdentity: Bool

    public init(
        bundleIdentifier: String,
        teamIdentifier: String,
        userIdentifier: UInt32,
        designatedRequirement: String,
        auditToken: AuditToken?,
        isDebugIdentity: Bool
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.userIdentifier = userIdentifier
        self.designatedRequirement = designatedRequirement
        self.auditToken = auditToken
        self.isDebugIdentity = isDebugIdentity
    }
}

/// The identity a caller must match, and the operations it may request.
public struct CallerPolicy: Sendable, Hashable {
    public let bundleIdentifier: String
    public let teamIdentifier: String
    public let userIdentifier: UInt32
    public let designatedRequirement: String
    public let permittedOperations: Set<BrokeredOperationKind>

    public init(
        bundleIdentifier: String,
        teamIdentifier: String,
        userIdentifier: UInt32,
        designatedRequirement: String,
        permittedOperations: Set<BrokeredOperationKind>
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.userIdentifier = userIdentifier
        self.designatedRequirement = designatedRequirement
        self.permittedOperations = permittedOperations
    }
}

/// Operation labels used for caller binding.
///
/// Kept here rather than on the contract request type so that adding a request
/// case cannot silently inherit an existing caller grant: a new operation must
/// be named here and granted explicitly.
public enum BrokeredOperationKind: String, Sendable, Hashable, CaseIterable, Codable {
    case availability

    public init(_ request: BrokeredRequest) {
        switch request {
        case .availability:
            self = .availability
        }
    }
}
