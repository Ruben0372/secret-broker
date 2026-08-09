import CryptoKit
import Foundation
import SecretBrokerContracts

public struct BootstrapReport: Sendable, Equatable {
    public let version: String
    public let capabilities: Set<RuntimeCapability>

    public init(version: String, capabilities: Set<RuntimeCapability>) {
        self.version = version
        self.capabilities = capabilities
    }
}

/// Foundations of the per-user daemon. IPC dispatch, caller identity, and
/// supervision arrive in later issues; this slice wires the custody seam and
/// proves the redacted receipt path with fakes.
public struct DaemonBootstrap: Sendable {
    private let custodian: any SecretCustodian
    /// Per-boot receipt key. Random, memory only, never persisted, logged, or
    /// exported, and discarded when the daemon process ends.
    private let receiptKey: SymmetricKey

    public init(custodian: any SecretCustodian) {
        self.custodian = custodian
        self.receiptKey = SymmetricKey(size: .bits256)
    }

    public func start() -> BootstrapReport {
        BootstrapReport(
            version: SecretBrokerVersion.current,
            capabilities: RuntimePolicy.capabilities
        )
    }

    public func handle(_ request: BrokeredRequest) async -> BrokeredReceipt {
        switch request {
        case .availability(let reference):
            let receiptDigest = digest(of: reference)
            do {
                let availability = try await custodian.availability(of: reference)
                switch availability {
                case .present:
                    return BrokeredReceipt(
                        requestDigest: receiptDigest,
                        resultClass: .availabilityConfirmed
                    )
                case .absent:
                    return BrokeredReceipt(
                        requestDigest: receiptDigest,
                        resultClass: .availabilityAbsent
                    )
                }
            } catch {
                // Fail closed: probe errors surface as an explicit result
                // class and are never retried implicitly.
                return BrokeredReceipt(
                    requestDigest: receiptDigest,
                    resultClass: .custodianUnavailable
                )
            }
        }
    }

    /// Receipts identify requests by digest so logs and receipts never carry
    /// reference text, which may hint at what a caller integrates with.
    ///
    /// Keyed with the per-boot key rather than hashed directly: the reference
    /// space is small and enumerable, so an unkeyed digest of a reference is
    /// recoverable by wordlist. Keying keeps receipts correlatable inside one
    /// boot and meaningless outside it.
    func digest(of reference: SecretReference) -> String {
        let canonical = "\(reference.namespace)\u{1F}\(reference.name)"
        let code = HMAC<SHA256>.authenticationCode(
            for: Data(canonical.utf8),
            using: receiptKey
        )
        return code.map { String(format: "%02x", $0) }.joined()
    }
}
