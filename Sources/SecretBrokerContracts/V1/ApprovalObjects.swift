import Foundation

/// The two approval domains. They must never be merged into one flow, one
/// credential, one evidence format, or one code path.
public enum ApprovalFamily: String, Sendable, Hashable, CaseIterable {
    case taskApproval = "armel.task-approval"
    case ownerControl = "armel.owner-control"
}

/// The seven object types across both families, each pinned to its schema
/// identifier, its family, and the key role that may carry it.
///
/// Role and family are properties of the TYPE, never read from the input. A
/// verifier that took the domain or the role from the object it is checking
/// would accept whatever an attacker wrote there, which is the substitution
/// this contract exists to refuse.
public enum ApprovalObjectType: String, Sendable, Hashable, CaseIterable {
    case taskManifest = "armel.task.manifest"
    case taskDecision = "armel.task.decision"
    case gatewayReceipt = "armel.gateway.receipt"
    case enrollmentRecord = "armel.enrollment.record"
    case ownerControlManifest = "armel.owner-control.manifest"
    case ownerControlDecision = "armel.owner-control.decision"
    case ownerControlContinuity = "armel.owner-control.continuity"

    public var schema: String { rawValue }

    public var family: ApprovalFamily {
        switch self {
        case .taskManifest, .taskDecision, .gatewayReceipt, .enrollmentRecord:
            return .taskApproval
        case .ownerControlManifest, .ownerControlDecision, .ownerControlContinuity:
            return .ownerControl
        }
    }

    /// The key role required to carry this object, or nil where the contract
    /// requires none. Recording is not deciding: the continuity recorder may
    /// not carry a decision and the decision signer may not carry a continuity
    /// record, so these are not interchangeable.
    public var requiredKeyRole: String? {
        switch self {
        case .taskManifest, .ownerControlManifest: return nil
        case .taskDecision: return "device-approval-signer"
        case .gatewayReceipt: return "gateway-receipt-signer"
        case .enrollmentRecord: return "enrollment-attester"
        case .ownerControlDecision: return "owner-control-signer"
        case .ownerControlContinuity: return "owner-control-continuity-recorder"
        }
    }
}

/// Why an object was refused for the type it was presented as.
public enum ApprovalRejection: String, Sendable, Hashable, CaseIterable {
    case schemaMismatch
    case domainMismatch
    case keyRoleMismatch
    case unsupportedVersion
    case unknownField
    case missingField
    case unenumeratedControlAction
    case invalidSequence
    case genesisLinkMismatch
    case nonAdvancingState
    case nonCanonicalEncoding
    case malformedEncoding
}

/// Form validation for an approval object presented as a specific type.
///
/// A validated object is a well-formed claim, never a permission. Nothing here
/// signs, verifies a signature, authorises, or executes.
public enum ApprovalObjectValidator {
    /// Control actions are enumerated, because widening is never implicit.
    public static let controlActionKinds: Set<String> = [
        "device.enroll", "device.revoke", "key.rotate", "policy.change", "retention.change",
    ]

    /// Sequence 0 links from here. An all-zero digest is not a state any real
    /// predecessor could produce, so it cannot be forged as one.
    public static let genesisDigest = String(repeating: "0", count: 64)

    /// The mandatory byte-level entry point.
    ///
    /// Canonical-on-input runs HERE, on the raw bytes, before anything parses
    /// them. That ordering is the whole point and is not an implementation
    /// detail: a validator whose only entry takes an already-parsed dictionary
    /// has already lost the duplicate-key ambiguity, because the parser
    /// silently discarded one of the two values before the validator ever ran.
    ///
    /// Concretely, an object carrying `domain` twice, once task-approval and
    /// once owner-control, is a different object to a reader that keeps the
    /// first key than to one that keeps the last. One set of bytes is then task
    /// authority to one implementation and owner control to another, decided by
    /// nothing but which parser happens to read it. Re-encoding collapses the
    /// duplicate to a single key, so the bytes differ from the input and this
    /// refuses, identically for both orderings and for every reader.
    ///
    /// Callers holding bytes must use this. `validate(_:as:)` on a parsed
    /// dictionary remains available for callers that legitimately already have
    /// a value, but it cannot see what the parse threw away.
    public static func validate(
        bytes: [UInt8],
        as type: ApprovalObjectType
    ) -> ApprovalRejection? {
        guard CanonicalJSON.isCanonical(bytes) else { return .nonCanonicalEncoding }
        guard let object = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else {
            return .malformedEncoding
        }
        return validate(object, as: type)
    }

    /// Validates `object` AS `type`. The expected schema, family and role come
    /// from `type`, so presenting a genuine object of one type where another is
    /// required is refused by construction rather than by remembering to check.
    ///
    /// Prefer `validate(bytes:as:)` when the bytes are available: this entry
    /// cannot detect a duplicate key, because the parse already resolved it.
    public static func validate(
        _ object: [String: Any],
        as type: ApprovalObjectType
    ) -> ApprovalRejection? {
        guard let schema = object["schema"] as? String else { return .missingField }
        guard schema == type.schema else { return .schemaMismatch }

        guard let version = object["schema_version"] as? Int else { return .missingField }
        guard version == 1 else { return .unsupportedVersion }

        guard let domain = object["domain"] as? String else { return .missingField }
        guard domain == type.family.rawValue else { return .domainMismatch }

        if let requiredRole = type.requiredKeyRole {
            guard let role = object["key_role"] as? String else { return .missingField }
            guard role == requiredRole else { return .keyRoleMismatch }
        } else if object["key_role"] != nil {
            // A manifest requires no key role, so carrying one is a widening
            // attempt rather than harmless extra data.
            return .keyRoleMismatch
        }

        if type == .ownerControlContinuity {
            // A continuity record is the only object here that makes a claim
            // about ordering, so it carries checks the others do not.
            guard let sequence = object["sequence"] as? Int else { return .missingField }
            guard sequence >= 0 else { return .invalidSequence }

            guard let previous = object["previous_state_digest"] as? String,
                  let next = object["new_state_digest"] as? String
            else { return .missingField }

            // A record that does not advance the state is not a control change.
            guard previous != next else { return .nonAdvancingState }

            // Sequence 0 must link from the genesis digest. Without this, a
            // chain could be re-rooted at an arbitrary state and still validate
            // pairwise, which is precisely the anchoring this layer does claim.
            if sequence == 0 {
                guard previous == genesisDigest else { return .genesisLinkMismatch }
            }
        }

        if type == .ownerControlManifest {
            guard let action = object["control_action"] as? [String: Any] else { return .missingField }
            guard let kind = action["kind"] as? String else { return .missingField }
            guard controlActionKinds.contains(kind) else { return .unenumeratedControlAction }
        }

        return nil
    }
}
