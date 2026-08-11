import CryptoKit
import Foundation

/// Vocabulary for typed operations, and the seam a provider implements.
///
/// This lives in contracts for the same reason the ledger seam does: a fake
/// provider ships in the adapters target, whose dependency list is pinned to
/// contracts alone. Putting the vocabulary here changes the dependency graph
/// not at all. Admitting core to the adapters allowlist would mean relaxing a
/// security pin so new code fits, which is the move to refuse.
///
/// Descriptors are keyed by `OperationName` rather than by the core-side
/// `BrokeredOperationKind`. That enum stays in core deliberately, so that
/// adding a request case cannot silently inherit an existing caller grant, and
/// moving it here to save a mapping would undo that. Core owns the mapping and
/// enforces that it is total.
///
/// THE NEGATIVE CAPABILITY, and which half of it lives here.
///
/// A generic proxy is an operation whose route or output is not bound to a
/// specific typed schema. The vocabulary below refuses to contain the parts one
/// would be assembled from: there is no command, argv or shell field kind, no
/// free-form or dictionary kind, and a route is an enumerated destination
/// rather than a string. Those operations are not refused, they are unsayable.
///
/// One kind, `rawSecretMaterial`, IS expressible and is refused at
/// registration. That is deliberate. A denylist you cannot spell is a denylist
/// you cannot exercise, and the refusal has to be testable to be worth
/// anything.

// MARK: Names

/// Stable name of a typed operation. Caller-visible, so validated here.
public struct OperationName: Sendable, Hashable, Codable, CustomStringConvertible, Comparable {
    public let value: String

    public var description: String { value }

    public static func < (lhs: OperationName, rhs: OperationName) -> Bool {
        lhs.value < rhs.value
    }

    public init(_ value: String) throws {
        guard !value.isEmpty, value.count <= 128 else {
            throw RegistrationRefusal.invalidOperationName
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        guard value.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw RegistrationRefusal.invalidOperationName
        }
        self.value = value
    }
}

// MARK: Refusals

/// Why a registration or an authorization was refused. Typed, so a caller
/// branches on a reason rather than parsing a string.
public enum RegistrationRefusal: String, Error, Sendable, Hashable, CaseIterable {
    case secretCapableOutputField
    case secretCapableInput
    case forbiddenOutputFieldName
    case duplicateFieldName
    case duplicateRegistration
    case unregisteredOperation
    case incompleteRegistry
    case ambiguousProvider
    case missingProvider
    case capabilityNotGranted
    case invalidOperationName
    case emptySchema
}

// MARK: Field vocabulary

/// Everything a schema field is allowed to be.
///
/// Closed by construction. There is no case for a command, an argument vector,
/// a URL, a dictionary, or a free-form value, so an operation that routes
/// arbitrary traffic or runs a program cannot be described at all.
public enum FieldKind: String, Sendable, Hashable, CaseIterable, Codable {
    case booleanFlag
    case enumeratedCode
    case digestHex
    /// Names a secret and cannot carry one. The ARM-26 discipline: custody
    /// hands back handles, never values.
    case credentialHandle
    case count
    case timestampSeconds
    case operationName
    case redactedReasonCode
    /// Expressible ONLY so that refusing it is testable. Never valid in an
    /// output schema, and never valid as an input either: a credential crosses
    /// as a handle in both directions.
    case rawSecretMaterial

    /// Exhaustive by construction. A new kind fails to compile until someone
    /// decides what it is, which is the point: the classification cannot be
    /// skipped, only made.
    public var isSecretCapable: Bool {
        switch self {
        case .rawSecretMaterial:
            return true
        case .booleanFlag, .enumeratedCode, .digestHex, .credentialHandle,
             .count, .timestampSeconds, .operationName, .redactedReasonCode:
            return false
        }
    }
}

public struct SchemaField: Sendable, Hashable, Codable {
    public let name: String
    public let kind: FieldKind
    public let isRequired: Bool

    public init(name: String, kind: FieldKind, isRequired: Bool) {
        self.name = name
        self.kind = kind
        self.isRequired = isRequired
    }
}

/// A closed field list. There is deliberately no flag admitting additional or
/// unknown fields: an open schema is the generic operation wearing a schema's
/// clothes, because anything at all can travel in the part nobody described.
public struct OperationSchema: Sendable, Hashable, Codable {
    public let fields: [SchemaField]

    public init(fields: [SchemaField]) {
        self.fields = fields
    }

    /// Names that must never appear in an output schema whatever their kind.
    ///
    /// Honest about what this is: the KIND check is the control, and this is a
    /// review aid on top of it, in the same spirit as the forbidden-token
    /// source scan. A field of a safe kind named `password` is far more likely
    /// to be a mistake than a design, and naming it here makes the mistake
    /// fail rather than ship.
    ///
    /// Every name here denotes a VALUE. `credential` was on this list and has
    /// been removed, because it names the CONCEPT rather than the value, and
    /// forbidding it made the sanctioned pattern, a field of kind
    /// `credentialHandle` called `credential`, impossible to register. A
    /// denylist that refuses the safe pattern pushes people toward the unsafe
    /// one, which is worse than not having the denylist. A positive control
    /// caught this; without one it would have shipped.
    public static let forbiddenOutputFieldNames: Set<String> = [
        "secret", "token", "password", "apikey", "api_key",
        "privatekey", "private_key", "bearer", "passphrase", "seed",
    ]

    func validatedAsOutput() throws {
        try validateShape()
        for field in fields {
            guard !field.kind.isSecretCapable else {
                throw RegistrationRefusal.secretCapableOutputField
            }
            guard !Self.forbiddenOutputFieldNames.contains(field.name.lowercased()) else {
                throw RegistrationRefusal.forbiddenOutputFieldName
            }
        }
    }

    func validatedAsInput() throws {
        try validateShape()
        for field in fields where field.kind.isSecretCapable {
            throw RegistrationRefusal.secretCapableInput
        }
    }

    private func validateShape() throws {
        var seen: Set<String> = []
        for field in fields {
            guard seen.insert(field.name.lowercased()).inserted else {
                throw RegistrationRefusal.duplicateFieldName
            }
        }
    }
}

// MARK: Operation shape

/// Where an operation goes. An enumerated destination, never a string, so a
/// caller cannot supply one and a new destination is a reviewed code change.
public enum OperationRoute: String, Sendable, Hashable, CaseIterable, Codable {
    case custodyAvailabilityProbe
    /// Exists for fake operations under test. It reaches nothing.
    case disposableTestSink
}

public enum OperationRisk: String, Sendable, Hashable, CaseIterable, Codable {
    case low
    case elevated
    case ownerControl
}

/// Retry is a property of the operation, declared once, rather than a decision
/// made at each call site. An operation that is not safe to repeat says so.
public enum RetryPolicy: String, Sendable, Hashable, CaseIterable, Codable {
    case never
    case idempotentOnly
}

public enum RedactionProfile: String, Sendable, Hashable, CaseIterable, Codable {
    case identifiersAndDigestsOnly
    case resultClassOnly
}

/// What a caller must hold to invoke an operation.
///
/// Distinct axis from the daemon's RuntimeCapability, which describes what the
/// runtime itself may do. This is what the CALLER must have been granted, and
/// conflating the two would let a capable runtime stand in for an entitled
/// caller.
public enum OperationCapability: String, Sendable, Hashable, CaseIterable, Codable {
    case availabilityProbe
    case credentialHandleUse
    case ownerControl
}

/// One typed operation. Every field is required: an operation that omitted its
/// risk, its retry policy or its redaction profile would be describing itself
/// only partly, and the missing part would be decided somewhere else.
public struct OperationDescriptor: Sendable, Hashable, Codable {
    public let name: OperationName
    public let input: OperationSchema
    public let output: OperationSchema
    public let route: OperationRoute
    public let risk: OperationRisk
    public let retry: RetryPolicy
    public let redaction: RedactionProfile
    public let requiredCapabilities: Set<OperationCapability>

    public init(
        name: OperationName,
        input: OperationSchema,
        output: OperationSchema,
        route: OperationRoute,
        risk: OperationRisk,
        retry: RetryPolicy,
        redaction: RedactionProfile,
        requiredCapabilities: Set<OperationCapability>
    ) {
        self.name = name
        self.input = input
        self.output = output
        self.route = route
        self.risk = risk
        self.retry = retry
        self.redaction = redaction
        self.requiredCapabilities = requiredCapabilities
    }

    /// Digest over every declared property, so drift in any of them is visible
    /// against a pin. Field order is preserved rather than sorted, because
    /// reordering a schema is a change to it.
    public var schemaDigest: String {
        var parts: [String] = [
            name.value, route.rawValue, risk.rawValue, retry.rawValue, redaction.rawValue,
            requiredCapabilities.map(\.rawValue).sorted().joined(separator: ","),
        ]
        for (label, schema) in [("in", input), ("out", output)] {
            for field in schema.fields {
                parts.append("\(label):\(field.name):\(field.kind.rawValue):\(field.isRequired)")
            }
        }
        var bytes = Array("armel.broker.operation.v1".utf8)
        for part in parts {
            bytes.append(0x00)
            bytes += Array(part.utf8)
        }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }

    public func validated() throws {
        try input.validatedAsInput()
        try output.validatedAsOutput()
    }

    public func withOutput(_ output: OperationSchema) -> OperationDescriptor {
        OperationDescriptor(
            name: name, input: input, output: output, route: route, risk: risk,
            retry: retry, redaction: redaction, requiredCapabilities: requiredCapabilities
        )
    }
}

/// What actually performs an operation. Implemented by fakes under test and, in
/// a later issue, by reviewed real providers.
public protocol OperationProvider: Sendable {
    var providerID: String { get }
    var handles: Set<OperationName> { get }
}
