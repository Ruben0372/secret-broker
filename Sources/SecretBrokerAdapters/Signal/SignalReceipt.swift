import CryptoKit
import Foundation

/// Evidence that a Signal message arrived, domain separated so it can never be
/// mistaken for an approval.
///
/// WHY A SEPARATE NAMESPACE RATHER THAN A NEW SigningContext CASE.
///
/// `SigningContext` is a VENDORED construction. Its tags, separator and covered
/// range are defined by the armel-approval repository, and this repository is a
/// downstream consumer holding it at ARM-14-pending. Adding
/// `armel.sig.v1.signal-evidence` to that enum would assert that the external
/// specification defines a Signal tag. It does not. That is the same
/// pinning-is-not-conformance hazard flagged in ARM-49, pointed the other way:
/// there the risk was reading a vendored vector as a conformance claim, here it
/// would be writing a local invention into a vendored vocabulary.
///
/// So Signal receipts live in `armel.broker.signal.v1.*`, which is this
/// repository's own namespace and says so. Separation is then not a property
/// anybody has to remember to check: the two constructions do not share a
/// prefix, and a digest computed under one does not reproduce under the other.
///
/// THE SEPARATOR, and why it is not NUL. The approval construction reserves
/// 0x00 and refuses any payload containing it. If this canonical form used NUL
/// the receipt could not even be PRESENTED to that construction, and a
/// separation test that cannot present the thing it is separating proves
/// nothing. Using 0x1F means a Signal receipt can be handed to the approval
/// preimage function, and still produces a different digest. The test is real
/// because the substitution is actually attempted.
public struct SignalReceipt: Sendable, Hashable, Codable, CustomStringConvertible {
    public static let evidenceDomainTag = "armel.broker.signal.v1.evidence"
    public static let stopDomainTag = "armel.broker.signal.v1.stop"

    /// Unit separator. Cannot appear in any field below, all of which are
    /// identifiers, hex digests or enumerated raw values.
    public static let fieldSeparator: UInt8 = 0x1F

    public let messageID: String
    public let senderIdentifier: String
    public let bodyDigest: String
    public let disposition: SignalDisposition
    public let domainTag: String
    public let digest: String

    public var description: String {
        // Names the message and its disposition. Never the body.
        "SignalReceipt(\(messageID) \(disposition.rawValue) under \(domainTag) digest \(digest.prefix(12)))"
    }

    /// Deterministic bytes covered by the digest, without the domain tag. The
    /// tag is prefixed at digest time rather than stored inside the covered
    /// range, so a receipt cannot restate its own domain and have the digest
    /// agree.
    public var canonicalBytes: [UInt8] {
        Self.canonicalBytes(
            messageID: messageID,
            senderIdentifier: senderIdentifier,
            bodyDigest: bodyDigest,
            disposition: disposition
        )
    }

    static func canonicalBytes(
        messageID: String,
        senderIdentifier: String,
        bodyDigest: String,
        disposition: SignalDisposition
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        for (index, field) in [messageID, senderIdentifier, bodyDigest, disposition.rawValue].enumerated() {
            if index > 0 { bytes.append(fieldSeparator) }
            bytes += Array(field.utf8)
        }
        return bytes
    }

    public init(
        messageID: String,
        senderIdentifier: String,
        bodyDigest: String,
        disposition: SignalDisposition
    ) {
        self.messageID = messageID
        self.senderIdentifier = senderIdentifier
        self.bodyDigest = bodyDigest
        self.disposition = disposition
        let tag: String
        switch disposition {
        case .evidence: tag = Self.evidenceDomainTag
        case .stop: tag = Self.stopDomainTag
        case .refused: tag = Self.evidenceDomainTag
        }
        self.domainTag = tag

        let covered = Self.canonicalBytes(
            messageID: messageID,
            senderIdentifier: senderIdentifier,
            bodyDigest: bodyDigest,
            disposition: disposition
        )
        // tag || 0x00 || canonical. Same shape as the approval construction so
        // the comparison is like for like, in a namespace that construction
        // does not use.
        let preimage = Array(tag.utf8) + [0x00] + covered
        self.digest = SHA256.hash(data: Data(preimage)).map { String(format: "%02x", $0) }.joined()
    }
}
