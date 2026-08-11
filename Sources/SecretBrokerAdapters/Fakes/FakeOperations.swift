import SecretBrokerContracts

/// Fake operations and providers for the registry tests.
///
/// Disposable by construction: the route is the test sink, which reaches
/// nothing, and no fake here holds a credential, opens a connection, or touches
/// the filesystem. They exist so refusals can be driven against something that
/// looks like a real registration rather than against a special case.
///
/// Note what these fakes CANNOT do, and that it is not politeness. There is no
/// way to write a fake that runs a command or routes arbitrary traffic, because
/// the field vocabulary has no part to build one from and the route is an
/// enumerated case. A fake is exactly as constrained as a real operation, which
/// is what makes it a fair test double rather than a friendlier one.
public enum FakeOperations {
    public static let name = "fake.operation.v1"

    public static func operationName() throws -> OperationName {
        try OperationName(name)
    }

    /// A descriptor that is valid unless a test deliberately makes it otherwise.
    public static func descriptor(
        output: OperationSchema? = nil,
        input: OperationSchema? = nil,
        requiring capabilities: Set<OperationCapability> = []
    ) throws -> OperationDescriptor {
        OperationDescriptor(
            name: try operationName(),
            input: input ?? OperationSchema(fields: [
                SchemaField(name: "subject", kind: .credentialHandle, isRequired: true)
            ]),
            output: output ?? OperationSchema(fields: [
                SchemaField(name: "resultClass", kind: .enumeratedCode, isRequired: true)
            ]),
            route: .disposableTestSink,
            risk: .low,
            retry: .never,
            redaction: .resultClassOnly,
            requiredCapabilities: capabilities
        )
    }

    public static func provider(id: String = "fake-provider") throws -> any OperationProvider {
        FakeOperationProvider(providerID: id, handles: [try operationName()])
    }
}

public struct FakeOperationProvider: OperationProvider {
    public let providerID: String
    public let handles: Set<OperationName>

    public init(providerID: String, handles: Set<OperationName>) {
        self.providerID = providerID
        self.handles = handles
    }
}
