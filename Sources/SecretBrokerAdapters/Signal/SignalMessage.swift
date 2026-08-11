import CryptoKit
import Foundation

/// Signal message vocabulary.
///
/// THE BOUNDARY THIS EXISTS TO HOLD: Signal supplies EVIDENCE or a fail-safe
/// STOP, and never task authority or approval by itself.
///
/// The strongest part of that is structural. `SignalDisposition` has no
/// authorizing case, so "Signal approved this" cannot be written down, in the
/// same way ARM-28's field vocabulary has no command kind. Everything else here
/// is a check, and every check is proven load-bearing by removing it.

/// A sender this broker is willing to hear from at all.
///
/// Both halves are pinned. The service identifier says who, and the safety
/// number says that the key backing that identity has not changed. An identity
/// alone is not enough: on Signal, a reset or a takeover keeps the identifier
/// and changes the safety number, which is exactly the case worth catching.
public struct SignalSender: Sendable, Hashable {
    public let serviceIdentifier: String
    public let safetyNumber: String

    public init(serviceIdentifier: String, safetyNumber: String) {
        self.serviceIdentifier = serviceIdentifier
        self.safetyNumber = safetyNumber
    }
}

/// What arrives from the transport, before anything has been decided about it.
public struct SignalEnvelope: Sendable, Hashable {
    public let messageID: String
    public let senderIdentifier: String
    public let safetyNumber: String
    public let body: String
    public let attachmentCount: Int

    public init(
        messageID: String,
        senderIdentifier: String,
        safetyNumber: String,
        body: String,
        attachmentCount: Int
    ) {
        self.messageID = messageID
        self.senderIdentifier = senderIdentifier
        self.safetyNumber = safetyNumber
        self.body = body
        self.attachmentCount = attachmentCount
    }
}

/// What a Signal message is permitted to mean.
///
/// There is deliberately no `approved`, `authorized` or equivalent case. That
/// is the acceptance property expressed in the type system rather than checked
/// at runtime: code downstream cannot branch on an authority that has no
/// representation.
public enum SignalDisposition: String, Sendable, Hashable, CaseIterable, Codable {
    case evidence
    case stop
    case refused

    /// Exhaustive, so a new disposition cannot arrive unclassified. If someone
    /// ever adds a case, this stops compiling until they say what it means.
    public var conveysAuthority: Bool {
        switch self {
        case .evidence, .stop, .refused:
            return false
        }
    }

    public var isActionable: Bool {
        switch self {
        case .evidence, .stop:
            return true
        case .refused:
            return false
        }
    }
}

public enum SignalRefusal: String, Error, Sendable, Hashable, CaseIterable {
    case senderNotPinned
    case safetyNumberDrift
    case grammarNotExact
    case bodyNotPlainAscii
    case attachmentPresent
    case duplicateMessage
    case transportOutage
    case emptyBody
    case realLinkageDisabled
}

/// Opaque reference to a received message.
///
/// Structurally cannot carry the body: there is no field that could hold it.
/// The ARM-26 discipline applied to a different payload, and for the same
/// reason. A layer that receives a handle can prove a message arrived and can
/// say which one, and cannot quote it or act on its contents.
public struct SignalHandle: Sendable, Hashable, CustomStringConvertible {
    public let messageID: String
    public let senderIdentifier: String
    public let bodyDigest: String

    public var description: String {
        // Names the message, never its contents.
        "SignalHandle(\(messageID) from \(senderIdentifier) body \(bodyDigest.prefix(12)))"
    }

    public init(messageID: String, senderIdentifier: String, bodyDigest: String) {
        self.messageID = messageID
        self.senderIdentifier = senderIdentifier
        self.bodyDigest = bodyDigest
    }
}

public struct SignalIngressResult: Sendable, Hashable {
    public let disposition: SignalDisposition
    public let handle: SignalHandle?
    public let receipt: SignalReceipt?
    public let refusal: SignalRefusal?
}

// MARK: Grammar

/// Parsing, and the asymmetry that is the whole design.
///
/// EVIDENCE FAILS CLOSED. The grammar is exact: ASCII printable only, single
/// spaces, exactly the expected tokens, nothing before and nothing after. Every
/// near miss is refused rather than repaired, because repairing is how a body
/// that is not the control grammar arrives as though it were.
///
/// STOP FAILS SAFE. It is deliberately permissive: case is folded, anything
/// that is not an ASCII letter or digit becomes a separator, and the tokens are
/// looked for anywhere in the message. A stop that only works on a well-formed
/// message fails exactly when the sender is in trouble and typing badly.
///
/// Making these equally strict breaks one of them in the dangerous direction.
/// A strict stop fails open when it is needed most; a permissive evidence path
/// promotes a near miss into a fact.
public enum SignalGrammar {
    public static let prefixToken = "ARMEL"
    public static let evidenceToken = "EVIDENCE"
    public static let stopToken = "STOP"

    /// Strict: exactly `ARMEL EVIDENCE <reference>`.
    public static func parseEvidenceReference(_ body: String) -> Result<String, SignalRefusal> {
        guard !body.isEmpty else { return .failure(.emptyBody) }

        // Printable ASCII only. This single rule removes the entire family of
        // folding attacks at once: zero-width joiners, non-breaking spaces,
        // fullwidth forms, bidirectional overrides, combining marks and
        // embedded NULs are all simply not representable in an accepted body.
        // Normalising them away would mean two different bodies could arrive
        // as one, and afterwards nothing could tell which had been sent.
        for scalar in body.unicodeScalars {
            guard scalar.value >= 0x20, scalar.value <= 0x7E else {
                return .failure(.bodyNotPlainAscii)
            }
        }

        // Empty components are kept, so a double space, a leading space or a
        // trailing space all produce the wrong token count rather than being
        // quietly collapsed.
        let tokens = body.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard tokens.count == 3 else { return .failure(.grammarNotExact) }
        guard tokens[0] == prefixToken, tokens[1] == evidenceToken else {
            return .failure(.grammarNotExact)
        }
        let reference = tokens[2]
        guard !reference.isEmpty, reference.count <= 64 else { return .failure(.grammarNotExact) }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        guard reference.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return .failure(.grammarNotExact)
        }
        return .success(reference)
    }

    /// Permissive: the stop tokens anywhere, in any case, through any damage.
    ///
    /// Token equality rather than substring containment, so STOPPED and
    /// STOPPAGE do not trigger a stop that nobody asked for.
    public static func containsStop(_ body: String) -> Bool {
        var tokens: [String] = []
        var current = ""
        for scalar in body.unicodeScalars {
            if let folded = Self.asciiAlphanumericUppercase(scalar) {
                current.unicodeScalars.append(folded)
            } else if !current.isEmpty {
                tokens.append(current)
                current = ""
            }
        }
        if !current.isEmpty { tokens.append(current) }

        guard let prefixIndex = tokens.firstIndex(of: prefixToken) else { return false }
        return tokens[prefixIndex...].contains(stopToken)
    }

    /// ASCII letters and digits only, uppercased. Everything else, including
    /// every non-ASCII scalar, reads as a separator. Deliberately not
    /// `uppercased()`: Unicode case folding is locale sensitive and maps
    /// characters across scripts, which is the opposite of what a fail-safe
    /// path wants.
    private static func asciiAlphanumericUppercase(_ scalar: Unicode.Scalar) -> Unicode.Scalar? {
        switch scalar.value {
        case 0x30...0x39, 0x41...0x5A:
            return scalar
        case 0x61...0x7A:
            return Unicode.Scalar(scalar.value - 32)
        default:
            return nil
        }
    }

    public static func bodyDigest(_ body: String) -> String {
        SHA256.hash(data: Data(body.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
