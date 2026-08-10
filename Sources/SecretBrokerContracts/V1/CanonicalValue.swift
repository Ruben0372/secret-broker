/// The five types the armel-authority-v1 family permits.
///
/// Everything else is excluded by the contract: negative integers, floats,
/// byte strings, null, undefined, and tags. Each excluded type is one fewer
/// path a peer must reproduce byte-identically, so the exclusion is modelled in
/// the type rather than checked at the edges. A value that cannot be spelled
/// cannot be encoded by accident.
public enum CanonicalValue: Sendable, Hashable {
    case unsigned(UInt64)
    case text(String)
    case boolean(Bool)
    case array([CanonicalValue])
    case map([String: CanonicalValue])
}

/// Refusal reasons, carrying the published reason codes verbatim.
///
/// The codes are part of the contract, not decoration: a peer that refuses for
/// the right reason with the wrong code has not reproduced the family. Every
/// refusal is a reason code and never a crash, which is why the decoder caps
/// nesting rather than exhausting its stack.
public enum CanonicalCBORError: Error, Sendable, Hashable {
    case noncanonicalEncoding(String)
    case duplicateField(String)
    case unsupportedType(String)
    case invalidUTF8
    case trailingBytes
    case nestingTooDeep
    case truncated

    public var reasonCode: String {
        switch self {
        case .noncanonicalEncoding: return "noncanonical_encoding"
        case .duplicateField: return "duplicate_field"
        case .unsupportedType: return "unsupported_type"
        case .invalidUTF8: return "invalid_utf8"
        case .trailingBytes: return "trailing_bytes"
        case .nestingTooDeep: return "nesting_too_deep"
        case .truncated: return "truncated"
        }
    }

    /// What actually went wrong, for a reader. The reason code is what a peer
    /// compares; this is what a human needs.
    public var detail: String {
        switch self {
        case .noncanonicalEncoding(let why): return why
        case .duplicateField(let key): return "duplicate map key \(key)"
        case .unsupportedType(let what): return what
        case .invalidUTF8: return "text is not strict UTF-8, or contains a surrogate"
        case .trailingBytes: return "bytes remain after the top-level item"
        case .nestingTooDeep: return "more than 32 nested containers"
        case .truncated: return "input ended inside an item"
        }
    }
}
