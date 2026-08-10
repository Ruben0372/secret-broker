import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// Typed operation registry, and the negative capability it exists to hold.
///
/// The acceptance is negative: NO generic proxy, NO command runner, NO
/// raw-secret-fetch operation exists. Every operation is a typed, registered
/// entry.
///
/// A negative capability proven by looking at what happens to be present is
/// worth very little, because the next commit can add the thing. So the proof
/// is split, and the split is stated rather than blurred:
///
/// LAYER 1, INEXPRESSIBLE. A generic proxy is an operation whose route or
/// output is not bound to a specific typed schema. There is no field kind for a
/// command, no field kind for a free-form value, and a route is an enumerated
/// case rather than a string. Those operations cannot be written down, so no
/// check has to catch them. This layer is pinned by DERIVING the vocabulary and
/// requiring every case to be classified, so a new kind cannot arrive
/// unclassified.
///
/// LAYER 2, EXPRESSIBLE AND REFUSED. Secret-capable output kinds and forbidden
/// output field names. These have to be constructible or the refusal could not
/// be tested at all: a denylist you cannot spell is a denylist you cannot
/// exercise. This layer is a check, not a guarantee, and every check here is
/// shown load-bearing by removing it and watching the bypass return.
///
/// Nothing here enumerates operations by hand (DISC-065). The authority for the
/// operation set is `BrokeredOperationKind.allCases`, and the registry must be
/// total and exclusive over it, so a new operation that is not typed and
/// registered fails rather than inheriting anything.

@Suite("Operation registry, typed entries and the negative capability")
struct OperationRegistryTests {
    // MARK: The acceptance, derived rather than enumerated

    @Test("Every registered operation is typed, and the registry covers exactly the operation set")
    func registryIsTotalAndExclusive() throws {
        let registry = try OperationRegistry.production()
        let covered = registry.coveredOperations

        // Derived from the type, never from a list written here. A new case
        // with no descriptor fails, which is the extension rule enforced
        // instead of documented.
        #expect(
            covered == Set(BrokeredOperationKind.allCases),
            "registry covers \(covered.map(\.rawValue).sorted()), the operation set is \(BrokeredOperationKind.allCases.map(\.rawValue).sorted())"
        )
        // POSITIVE CONTROL: a registry covering nothing would satisfy every
        // must-not assertion below while describing no operations at all.
        #expect(!covered.isEmpty, "the registry describes no operations, so nothing below was tested")
    }

    @Test("No registered operation can return secret material or route arbitrary traffic")
    func noRegisteredOperationIsGeneric() throws {
        let registry = try OperationRegistry.production()
        var checked = 0
        for kind in registry.coveredOperations.sorted(by: { $0.rawValue < $1.rawValue }) {
            let descriptor = try registry.descriptor(for: kind)
            for field in descriptor.output.fields {
                #expect(
                    !field.kind.isSecretCapable,
                    "\(kind.rawValue) output field \(field.name) is of secret-capable kind \(field.kind.rawValue)"
                )
                #expect(
                    !OperationSchema.forbiddenOutputFieldNames.contains(field.name.lowercased()),
                    "\(kind.rawValue) output carries a forbidden field name: \(field.name)"
                )
            }
            for field in descriptor.input.fields {
                #expect(
                    field.kind != .rawSecretMaterial,
                    "\(kind.rawValue) accepts raw secret material as input; credentials cross as handles"
                )
            }
            checked += 1
        }
        #expect(checked == BrokeredOperationKind.allCases.count, "checked \(checked) operations")
    }

    // MARK: Layer 1, the vocabulary cannot express the forbidden shapes

    @Test("Every field kind is explicitly classified, so a new one cannot arrive unclassified")
    func fieldKindsAreAllClassified() {
        // isSecretCapable is an exhaustive switch over the enum, so this cannot
        // silently miss a case: a new kind fails to compile until someone
        // decides what it is. This test asserts the classification is real
        // rather than uniformly false, which is the way it could be present and
        // useless.
        let kinds = FieldKind.allCases
        #expect(kinds.count > 1, "the field vocabulary has \(kinds.count) kinds, too few to be real")
        #expect(
            kinds.contains(where: { $0.isSecretCapable }),
            "no field kind is classified secret-capable, so the classification never refuses anything"
        )
        #expect(
            kinds.contains(where: { !$0.isSecretCapable }),
            "every field kind is secret-capable, so no operation could ever be registered"
        )
    }

    /// The reviewed vocabulary, pinned exactly.
    ///
    /// This is the control; the substring scans below are the readable failure
    /// on top of it. The distinction matters, and it is the difference between
    /// a guarantee and a habit: a scan for command-shaped names catches
    /// `.commandLine` and misses `.payload`, `.opaqueBlob` or `.freeText`, any
    /// of which is a generic escape wearing an innocuous name. Only an exact
    /// set makes EVERY addition fail until somebody reviews it, which is the
    /// property Layer 1 actually needs.
    ///
    /// Extending either set is a reviewed act. If a new case belongs here, add
    /// it deliberately and say why. Do not widen the pin to make a build pass.
    @Test("The capability-bearing vocabularies are exactly the reviewed sets")
    func vocabulariesMatchTheReviewedSets() {
        #expect(
            Set(FieldKind.allCases.map(\.rawValue)) == [
                "booleanFlag", "enumeratedCode", "digestHex", "credentialHandle",
                "count", "timestampSeconds", "operationName", "redactedReasonCode",
                "rawSecretMaterial",
            ],
            "the field vocabulary changed: \(FieldKind.allCases.map(\.rawValue).sorted()). A new kind widens what an operation can be, and is a reviewed change."
        )
        #expect(
            Set(OperationRoute.allCases.map(\.rawValue)) == [
                "custodyAvailabilityProbe", "disposableTestSink",
            ],
            "the route set changed: \(OperationRoute.allCases.map(\.rawValue).sorted()). A new route is a new destination, and is a reviewed change."
        )
        #expect(
            Set(OperationCapability.allCases.map(\.rawValue)) == [
                "availabilityProbe", "credentialHandleUse", "ownerControl",
            ],
            "the capability set changed: \(OperationCapability.allCases.map(\.rawValue).sorted()). A new capability is a new thing a caller can be granted."
        )
    }

    @Test("The field vocabulary contains no command-shaped or free-form kind")
    func fieldVocabularyHasNoEscapeHatch() {
        // A command runner and a generic proxy are built out of parts. If no
        // part exists, neither does the operation. Derived from allCases so a
        // newly added kind is scanned automatically.
        let escapes = ["command", "argv", "shell", "exec", "script", "url", "endpoint", "any", "arbitrary", "dictionary", "json", "freeform", "passthrough", "proxy"]
        for kind in FieldKind.allCases {
            let name = kind.rawValue.lowercased()
            for escape in escapes {
                #expect(
                    !name.contains(escape),
                    "field kind \(kind.rawValue) matches the escape family \(escape); a generic operation could be built from it"
                )
            }
        }
        // POSITIVE CONTROL: the scan can see an escape when one is present.
        #expect(escapes.contains(where: { "commandLine".lowercased().contains($0) }))
    }

    @Test("A route is an enumerated destination, never a caller-supplied one")
    func routesAreEnumerated() {
        let routes = OperationRoute.allCases
        #expect(!routes.isEmpty, "no routes are declared, so the scan below checks nothing")
        let escapes = ["url", "http", "host", "endpoint", "any", "arbitrary", "proxy", "forward", "passthrough"]
        for route in routes {
            let name = route.rawValue.lowercased()
            for escape in escapes {
                #expect(
                    !name.contains(escape),
                    "route \(route.rawValue) matches the escape family \(escape); it may not be a fixed destination"
                )
            }
        }
    }

    // MARK: Layer 2, refusals, each with a positive control

    @Test("An operation returning raw secret material cannot be registered")
    func secretCapableOutputIsRefused() throws {
        let generic = try FakeOperations.descriptor(
            output: OperationSchema(fields: [
                SchemaField(name: "value", kind: .rawSecretMaterial, isRequired: true)
            ])
        )
        #expect(throws: RegistrationRefusal.self, "an operation returning raw secret material was registered") {
            _ = try OperationRegistry.build(descriptors: [generic], providers: [try FakeOperations.provider()])
        }

        // POSITIVE CONTROL: the same operation returning a HANDLE is accepted,
        // so the refusal is about the secret crossing rather than about the
        // registry refusing everything.
        let handled = try FakeOperations.descriptor(
            output: OperationSchema(fields: [
                SchemaField(name: "credential", kind: .credentialHandle, isRequired: true)
            ])
        )
        let registry = try OperationRegistry.build(
            descriptors: [handled],
            providers: [try FakeOperations.provider()]
        )
        #expect(registry.registeredNames == [try FakeOperations.operationName()])
    }

    /// The input direction, which the production scan asserts but nothing was
    /// driving. A registry that refused secret material on the way out and
    /// accepted it on the way in would still be a raw-secret-fetch operation,
    /// just one where the caller supplies the secret instead of receiving it.
    @Test("An operation accepting raw secret material as input cannot be registered")
    func secretCapableInputIsRefused() throws {
        let descriptor = try FakeOperations.descriptor(
            input: OperationSchema(fields: [
                SchemaField(name: "material", kind: .rawSecretMaterial, isRequired: true)
            ])
        )
        #expect(throws: RegistrationRefusal.self, "an operation accepting raw secret material was registered") {
            _ = try OperationRegistry.build(
                descriptors: [descriptor],
                providers: [try FakeOperations.provider()]
            )
        }

        // POSITIVE CONTROL: the handle form of the same input is accepted.
        let handled = try FakeOperations.descriptor(
            input: OperationSchema(fields: [
                SchemaField(name: "material", kind: .credentialHandle, isRequired: true)
            ])
        )
        _ = try OperationRegistry.build(
            descriptors: [handled],
            providers: [try FakeOperations.provider()]
        )
    }

    @Test("An operation whose output carries a forbidden field name cannot be registered")
    func forbiddenOutputFieldNameIsRefused() throws {
        for forbidden in OperationSchema.forbiddenOutputFieldNames.sorted() {
            let descriptor = try FakeOperations.descriptor(
                output: OperationSchema(fields: [
                    SchemaField(name: forbidden, kind: .digestHex, isRequired: true)
                ])
            )
            #expect(
                throws: RegistrationRefusal.self,
                "an output field named \(forbidden) was registered"
            ) {
                _ = try OperationRegistry.build(
                    descriptors: [descriptor],
                    providers: [try FakeOperations.provider()]
                )
            }
        }
        #expect(
            OperationSchema.forbiddenOutputFieldNames.count >= 5,
            "the forbidden name list has \(OperationSchema.forbiddenOutputFieldNames.count) entries, too few to be real"
        )
        // The sanctioned pattern must stay registerable. A denylist broad
        // enough to refuse `credential` on a field of kind credentialHandle
        // pushes an author toward a worse shape, which is how a safety list
        // becomes a hazard. This assertion is why that was caught.
        #expect(
            !OperationSchema.forbiddenOutputFieldNames.contains("credential"),
            "the denylist refuses the safe credential-handle pattern by name"
        )

        // POSITIVE CONTROL: an ordinary name of the same kind is accepted.
        let ordinary = try FakeOperations.descriptor(
            output: OperationSchema(fields: [
                SchemaField(name: "requestDigest", kind: .digestHex, isRequired: true)
            ])
        )
        _ = try OperationRegistry.build(descriptors: [ordinary], providers: [try FakeOperations.provider()])
    }

    @Test("An unknown operation is refused")
    func unknownOperationIsRefused() throws {
        // A registry describing nothing still answers, and answers by refusing.
        // Failing open here would mean an unregistered operation resolved to
        // whatever a caller asked for, which is the generic escape arriving
        // through the lookup rather than through the vocabulary.
        let empty = try OperationRegistry.build(descriptors: [], providers: [])
        for kind in BrokeredOperationKind.allCases {
            #expect(throws: RegistrationRefusal.self, "\(kind.rawValue) resolved against an empty registry") {
                _ = try empty.descriptor(for: kind)
            }
            #expect(throws: RegistrationRefusal.self) { _ = try empty.provider(for: kind) }
        }

        // POSITIVE CONTROL: the production registry resolves every operation,
        // so the refusals above are about absence rather than about a lookup
        // that never succeeds.
        let registry = try OperationRegistry.production()
        for kind in BrokeredOperationKind.allCases {
            #expect(throws: Never.self) { _ = try registry.descriptor(for: kind) }
        }
    }

    @Test("A registry that does not cover every operation is refused")
    func incompleteRegistryIsRefused() throws {
        // The extension rule, enforced: a new operation that is not typed and
        // registered cannot ship. Building with no descriptors stands in for
        // the case where someone adds an operation and forgets the descriptor.
        #expect(throws: RegistrationRefusal.self, "an empty registry was accepted as covering the operation set") {
            _ = try OperationRegistry.buildProduction(descriptors: [], providers: [])
        }
        // POSITIVE CONTROL: the real production set does build.
        #expect(throws: Never.self) { _ = try OperationRegistry.production() }
    }

    @Test("Schema drift is detected against the pinned digests")
    func schemaDriftIsDetected() throws {
        let registry = try OperationRegistry.production()
        var checked = 0
        for kind in registry.coveredOperations {
            let descriptor = try registry.descriptor(for: kind)
            let pinned = try #require(
                Self.pinnedSchemaDigests[kind],
                "\(kind.rawValue) has no pinned schema digest; a new operation must be pinned, not defaulted"
            )
            #expect(
                descriptor.schemaDigest == pinned,
                "\(kind.rawValue) schema digests to \(descriptor.schemaDigest), pinned \(pinned). If this change is intended, re-pin deliberately."
            )
            checked += 1
        }
        #expect(checked == BrokeredOperationKind.allCases.count)

        // POSITIVE CONTROL that the digest actually depends on the schema: the
        // same descriptor with one extra output field must digest differently.
        // A digest that ignored the schema would pass everything above.
        let descriptor = try registry.descriptor(for: try #require(registry.coveredOperations.first))
        let drifted = descriptor.withOutput(
            OperationSchema(fields: descriptor.output.fields + [
                SchemaField(name: "extra", kind: .count, isRequired: false)
            ])
        )
        #expect(drifted.schemaDigest != descriptor.schemaDigest, "the schema digest does not depend on the schema")
    }

    @Test("An operation requiring a capability the caller lacks is refused")
    func capabilityMismatchIsRefused() throws {
        let descriptor = try FakeOperations.descriptor(requiring: [.credentialHandleUse])
        let registry = try OperationRegistry.build(
            descriptors: [descriptor],
            providers: [try FakeOperations.provider()]
        )

        #expect(throws: RegistrationRefusal.self, "an operation ran without the capability it requires") {
            _ = try registry.authorize(named: try FakeOperations.operationName(), grantedCapabilities: [])
        }
        #expect(throws: RegistrationRefusal.self, "a partially granted caller was authorized") {
            _ = try registry.authorize(named: try FakeOperations.operationName(), grantedCapabilities: [.availabilityProbe])
        }

        // POSITIVE CONTROL: the caller holding the capability is authorized, so
        // the refusals are about the grant rather than about a registry that
        // authorizes nobody.
        let authorized = try registry.authorize(
            named: try FakeOperations.operationName(),
            grantedCapabilities: [.credentialHandleUse]
        )
        #expect(authorized.name == (try FakeOperations.operationName()))

        // A superset also passes: holding more than required is not a reason to
        // refuse, and asserting it keeps the check from being an equality test
        // that would refuse a legitimately broader caller.
        #expect(throws: Never.self) {
            _ = try registry.authorize(
                named: try FakeOperations.operationName(),
                grantedCapabilities: [.credentialHandleUse, .availabilityProbe]
            )
        }
    }

    @Test("Two providers for one operation is refused, never silently resolved")
    func providerAmbiguityIsRefused() throws {
        let descriptor = try FakeOperations.descriptor()
        let first = try FakeOperations.provider(id: "provider-a")
        let second = try FakeOperations.provider(id: "provider-b")

        #expect(throws: RegistrationRefusal.self, "two providers for one operation resolved silently") {
            _ = try OperationRegistry.build(descriptors: [descriptor], providers: [first, second])
        }

        // Order must not change the answer. A registry that picked the first
        // registered provider would pass the assertion above only by accident
        // of ordering, and would silently pick in production.
        #expect(throws: RegistrationRefusal.self) {
            _ = try OperationRegistry.build(descriptors: [descriptor], providers: [second, first])
        }

        // POSITIVE CONTROL: exactly one provider resolves.
        let registry = try OperationRegistry.build(descriptors: [descriptor], providers: [first])
        let resolved = try registry.provider(named: try FakeOperations.operationName())
        #expect(resolved.providerID == "provider-a")
    }

    @Test("An operation with no provider is refused")
    func missingProviderIsRefused() throws {
        #expect(throws: RegistrationRefusal.self, "an operation with no provider was registered") {
            _ = try OperationRegistry.build(descriptors: [try FakeOperations.descriptor()], providers: [])
        }
    }

    @Test("A schema cannot declare the same field twice")
    func duplicateFieldNamesAreRefused() throws {
        let descriptor = try FakeOperations.descriptor(
            output: OperationSchema(fields: [
                SchemaField(name: "requestDigest", kind: .digestHex, isRequired: true),
                SchemaField(name: "requestDigest", kind: .count, isRequired: false),
            ])
        )
        #expect(throws: RegistrationRefusal.self, "a schema declaring one field twice was registered") {
            _ = try OperationRegistry.build(descriptors: [descriptor], providers: [try FakeOperations.provider()])
        }
    }

    // MARK: Pinned schema digests

    /// One pinned digest per operation. This is deliberately NOT derived from
    /// the descriptor: a pin that moves with the thing it pins detects nothing.
    /// Re-pinning is a reviewed act, and an operation with no entry fails the
    /// drift test rather than defaulting to whatever it currently is.
    static let pinnedSchemaDigests: [BrokeredOperationKind: String] = [
        .availability: "3a92fc160adaa251f47b1ad1fbc2a951cd9e5770ee88f93ed28c3f3dc118eb5c"
    ]
}
