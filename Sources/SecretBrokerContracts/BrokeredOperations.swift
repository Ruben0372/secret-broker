/// Typed request, result, and receipt schemas for the v1.0.1 foundations.
///
/// Deliberate constraint: no type in this module can carry secret material,
/// so a caller cannot obtain a value, token, or environment export through
/// the contract surface at all. Narrow value handling arrives later inside
/// dedicated custody modules, never in caller-facing schemas.
public enum BrokeredRequest: Sendable, Hashable, Codable {
    case availability(SecretReference)
}

public enum SecretAvailability: String, Sendable, Codable {
    case present
    case absent
}

public enum BrokeredResultClass: String, Sendable, Codable {
    case availabilityConfirmed
    case availabilityAbsent
    /// Fail-closed class for custodian probe errors; never retried implicitly.
    case custodianUnavailable
}

/// Redacted outcome evidence. Identifies the request by digest only.
public struct BrokeredReceipt: Sendable, Hashable, Codable {
    public let requestDigest: String
    public let resultClass: BrokeredResultClass

    public init(requestDigest: String, resultClass: BrokeredResultClass) {
        self.requestDigest = requestDigest
        self.resultClass = resultClass
    }
}

/// Custody seam the daemon consumes. Intentionally has no operation that
/// returns secret material; a real Keychain custodian ships in a later issue
/// as its own module behind this same seam.
public protocol SecretCustodian: Sendable {
    func availability(of reference: SecretReference) async throws -> SecretAvailability
}
