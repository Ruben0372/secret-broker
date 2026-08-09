import SecretBrokerContracts

/// Custody double backed by an in-memory set of references.
///
/// Disposable state only: no Keychain, no credentials, no environment, no
/// filesystem, no network. It answers availability from what the test handed
/// it and cannot hold or return secret material, because the contracts seam
/// has no operation that carries a value.
public struct InMemorySecretCustodian: SecretCustodian {
    private let known: Set<SecretReference>

    public init(known: Set<SecretReference>) {
        self.known = known
    }

    public func availability(of reference: SecretReference) async throws -> SecretAvailability {
        known.contains(reference) ? .present : .absent
    }
}

/// Custody double that always fails, used to prove the daemon fails closed on
/// an ambiguous or broken custodian probe rather than assuming absence.
public struct FailingSecretCustodian: SecretCustodian {
    public struct ProbeFailure: Error {
        public init() {}
    }

    public init() {}

    public func availability(of reference: SecretReference) async throws -> SecretAvailability {
        throw ProbeFailure()
    }
}
