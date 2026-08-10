import CryptoKit
import Foundation

/// Domain-separated signing preimages for the approval families.
///
///     tag || 0x00 || canonical_bytes
///
/// Why this is stronger than the audience field, and why both exist. Audience
/// is data, so it protects only against a validator that remembers to check it;
/// a validator that forgets is a defect that silently lets evidence cross the
/// boundary. The signing context fails closed even against that forgetful
/// validator, because the covered bytes differ in a prefix neither party
/// controls, so the signature simply does not verify.
///
/// The tag is deliberately NOT a field of any object. It is derived from the
/// object type being verified, so a caller cannot supply one, and cannot
/// substitute one by editing the input. That is the property the whole
/// separation rests on, so it is expressed as a function of the type rather
/// than as a lookup on parsed data.
///
/// PROVENANCE, and it matters. This construction is a LOCAL DEFINITION of the
/// armel-approval repository, not a pinned external standard. The tag strings,
/// the separator, the covered range, and the one-tag-per-domain rule are all
/// defined there. Confirm-or-freeze is tracked as DISC-042 against ARM-14, and
/// this repository is a downstream consumer: if the tags, the separator, or the
/// covered range change, every owner-control vector digest moves and these
/// constants must be re-pinned. They are marked pending for that reason.
public enum SigningContext: Sendable, Hashable, CaseIterable {
    case taskApproval
    case ownerControl

    /// ARM-14-pending: enforced now, re-pinned if the architecture decision
    /// freezes a different construction.
    public static let disc042Status = "ARM-14-pending: local definition, confirm-or-freeze not yet decided"

    public var tag: String {
        switch self {
        case .taskApproval: return "armel.sig.v1.task-approval"
        case .ownerControl: return "armel.sig.v1.owner-control"
        }
    }

    /// The separator. A canonical encoding can never contain a raw NUL, which
    /// is what makes tag and payload unambiguous; the guard below refuses
    /// rather than trusting that invariant silently.
    public static let separator: UInt8 = 0x00

    /// Derives the context from the object type. There is deliberately no
    /// initialiser that reads a tag from input.
    public static func forObjectType(_ type: ApprovalObjectType) -> SigningContext {
        switch type.family {
        case .taskApproval: return .taskApproval
        case .ownerControl: return .ownerControl
        }
    }

    public enum PreimageError: Error, Sendable, Hashable {
        case separatorInTag(String)
        case separatorInCanonicalBytes
    }

    public func preimage(canonicalBytes: [UInt8]) throws -> [UInt8] {
        let tagBytes = Array(tag.utf8)
        guard !tagBytes.contains(Self.separator) else {
            throw PreimageError.separatorInTag(tag)
        }
        // Fail closed if a canonical encoding ever carried a raw NUL: the
        // construction's injectivity depends on that never happening, and an
        // unchecked assumption is how a boundary quietly stops holding.
        guard !canonicalBytes.contains(Self.separator) else {
            throw PreimageError.separatorInCanonicalBytes
        }
        return tagBytes + [Self.separator] + canonicalBytes
    }

    public func preimage(canonicalJSON: String) throws -> [UInt8] {
        try preimage(canonicalBytes: Array(canonicalJSON.utf8))
    }

    public func preimageDigestHex(canonicalJSON: String) throws -> String {
        let bytes = try preimage(canonicalJSON: canonicalJSON)
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
}
