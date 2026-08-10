import SecretBrokerContracts

/// The registry of typed operations.
///
/// ACCEPTANCE: no generic proxy, no command runner, no raw-secret-fetch
/// operation exists. Every operation is a typed, registered entry.
///
/// Most of that is carried by the vocabulary in contracts, where a command or
/// an arbitrary destination simply cannot be written down. What is left for the
/// registry is the part that IS expressible and must be refused, plus the one
/// property the vocabulary cannot express on its own: that the set of typed
/// entries covers the set of operations exactly.
///
/// # Extension rules
///
/// These are enforced here, not merely written down, because a documented rule
/// that nothing checks is a rule that lasts until the first hurry.
///
/// 1. A new operation MUST have a `BrokeredOperationKind` case, a name via the
///    exhaustive mapping below, and a typed descriptor. Miss any one and the
///    production registry refuses to build.
/// 2. A new operation CANNOT be a generic escape. It is described in the closed
///    field vocabulary or it is not describable.
/// 3. A new operation MUST declare its route, risk, retry policy, redaction
///    profile and required capabilities. There are no defaults, because a
///    default is a decision made by whoever wrote the default rather than by
///    whoever added the operation.
/// 4. A new operation MUST be pinned by schema digest in the test suite. An
///    operation with no pin fails rather than adopting whatever it currently
///    is.
/// 5. Exactly one provider handles an operation. Zero is refused and two are
///    refused; neither is resolved by picking.
public struct OperationRegistry: Sendable {
    private let descriptors: [OperationName: OperationDescriptor]
    private let providers: [OperationName: any OperationProvider]
    private let namesByKind: [BrokeredOperationKind: OperationName]

    /// Every operation kind's stable name.
    ///
    /// An exhaustive switch, so a new kind cannot reach the registry unnamed.
    /// This is the mapping that lets descriptors live in contracts while the
    /// caller-grant enum stays in core where adding a case cannot silently
    /// inherit a grant.
    public static func name(of kind: BrokeredOperationKind) throws -> OperationName {
        switch kind {
        case .availability:
            return try OperationName("broker.availability.v1")
        }
    }

    /// The operations this registry describes, as core-side kinds.
    public var coveredOperations: Set<BrokeredOperationKind> {
        Set(namesByKind.filter { descriptors[$0.value] != nil }.keys)
    }

    // MARK: Building

    /// Validates and builds a registry over exactly the descriptors given.
    ///
    /// Does NOT require coverage of the whole operation set: that is what
    /// `buildProduction` is for, and separating them means the refusal tests
    /// can build a registry containing one fake operation without every test
    /// also having to satisfy totality.
    public static func build(
        descriptors: [OperationDescriptor],
        providers: [any OperationProvider]
    ) throws -> OperationRegistry {
        var byName: [OperationName: OperationDescriptor] = [:]
        for descriptor in descriptors {
            // Validate BEFORE inserting. A refused descriptor must leave the
            // registry with no trace of itself, the same discipline the ledger
            // uses for a refused write.
            try descriptor.validated()
            guard byName.updateValue(descriptor, forKey: descriptor.name) == nil else {
                throw RegistrationRefusal.duplicateRegistration
            }
        }

        // Exactly one provider per described operation. Ambiguity is refused
        // rather than resolved: picking one would be a decision made by
        // registration order, which is not a decision anyone made.
        var byProvider: [OperationName: any OperationProvider] = [:]
        var claimed: [OperationName: Int] = [:]
        for provider in providers {
            for name in provider.handles {
                claimed[name, default: 0] += 1
                if byProvider[name] == nil {
                    byProvider[name] = provider
                }
            }
        }
        for (name, _) in byName {
            switch claimed[name] ?? 0 {
            case 0: throw RegistrationRefusal.missingProvider
            case 1: break
            default: throw RegistrationRefusal.ambiguousProvider
            }
        }

        var namesByKind: [BrokeredOperationKind: OperationName] = [:]
        for kind in BrokeredOperationKind.allCases {
            namesByKind[kind] = try name(of: kind)
        }
        return OperationRegistry(descriptors: byName, providers: byProvider, namesByKind: namesByKind)
    }

    /// Builds and additionally requires that the descriptors cover the
    /// operation set exactly: total, so no operation is undescribed, and
    /// exclusive, so no descriptor describes something that is not an
    /// operation.
    public static func buildProduction(
        descriptors: [OperationDescriptor],
        providers: [any OperationProvider]
    ) throws -> OperationRegistry {
        let registry = try build(descriptors: descriptors, providers: providers)
        var required: Set<OperationName> = []
        for kind in BrokeredOperationKind.allCases {
            required.insert(try name(of: kind))
        }
        guard Set(registry.descriptors.keys) == required else {
            throw RegistrationRefusal.incompleteRegistry
        }
        return registry
    }

    // MARK: The production set

    /// The operations that actually exist.
    ///
    /// Availability answers present or absent and nothing else. Its output
    /// carries a result class and a request digest: enough to know what
    /// happened, not enough to learn anything about the secret.
    public static func production() throws -> OperationRegistry {
        let availability = OperationDescriptor(
            name: try name(of: .availability),
            input: OperationSchema(fields: [
                SchemaField(name: "reference", kind: .credentialHandle, isRequired: true)
            ]),
            output: OperationSchema(fields: [
                SchemaField(name: "resultClass", kind: .enumeratedCode, isRequired: true),
                SchemaField(name: "requestDigest", kind: .digestHex, isRequired: true),
            ]),
            route: .custodyAvailabilityProbe,
            risk: .low,
            retry: .idempotentOnly,
            redaction: .identifiersAndDigestsOnly,
            requiredCapabilities: [.availabilityProbe]
        )
        return try buildProduction(
            descriptors: [availability],
            providers: [CustodyAvailabilityProvider()]
        )
    }

    // MARK: Resolution

    /// Everything this registry describes, by name. Includes entries that are
    /// not core-side operation kinds, which is how a fake operation is
    /// addressable under test without being reachable in production.
    public var registeredNames: Set<OperationName> {
        Set(descriptors.keys)
    }

    public func descriptor(named name: OperationName) throws -> OperationDescriptor {
        guard let descriptor = descriptors[name] else {
            throw RegistrationRefusal.unregisteredOperation
        }
        return descriptor
    }

    public func provider(named name: OperationName) throws -> any OperationProvider {
        guard let provider = providers[name] else {
            throw RegistrationRefusal.missingProvider
        }
        return provider
    }

    public func authorize(
        named name: OperationName,
        grantedCapabilities: Set<OperationCapability>
    ) throws -> OperationDescriptor {
        let descriptor = try descriptor(named: name)
        guard descriptor.requiredCapabilities.isSubset(of: grantedCapabilities) else {
            throw RegistrationRefusal.capabilityNotGranted
        }
        return descriptor
    }

    public func descriptor(for kind: BrokeredOperationKind) throws -> OperationDescriptor {
        guard let name = namesByKind[kind], let descriptor = descriptors[name] else {
            throw RegistrationRefusal.unregisteredOperation
        }
        return descriptor
    }

    public func provider(for kind: BrokeredOperationKind) throws -> any OperationProvider {
        guard let name = namesByKind[kind], let provider = providers[name] else {
            throw RegistrationRefusal.missingProvider
        }
        return provider
    }

    /// Resolves an operation for a caller holding `grantedCapabilities`.
    ///
    /// Superset, not equality: holding more than the operation requires is not
    /// a reason to refuse. Requiring equality would refuse a legitimately
    /// broader caller and, worse, would tempt someone to widen the operation's
    /// requirements to match a caller rather than the other way round.
    public func authorize(
        _ kind: BrokeredOperationKind,
        grantedCapabilities: Set<OperationCapability>
    ) throws -> OperationDescriptor {
        let descriptor = try descriptor(for: kind)
        guard descriptor.requiredCapabilities.isSubset(of: grantedCapabilities) else {
            throw RegistrationRefusal.capabilityNotGranted
        }
        return descriptor
    }
}

/// Provider for the availability probe. Names the operation it handles and
/// nothing else; the custody work itself lives behind the contracts seam.
struct CustodyAvailabilityProvider: OperationProvider {
    let providerID = "broker.custody.availability"

    var handles: Set<OperationName> {
        (try? OperationRegistry.name(of: .availability)).map { [$0] } ?? []
    }
}
