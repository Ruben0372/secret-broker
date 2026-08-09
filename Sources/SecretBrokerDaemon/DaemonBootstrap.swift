import CryptoKit
import Foundation
import SecretBrokerContracts
import SecretBrokerCore

/// Result of a caller-bound request: either a redacted receipt, or the reason
/// the caller was refused. A denial never carries a receipt, so a refused call
/// cannot be mistaken for a completed one.
public enum DaemonOutcome: Sendable, Hashable {
    case completed(BrokeredReceipt)
    case denied(CallerDenial)
}

public struct BootstrapReport: Sendable, Equatable {
    public let version: String
    public let capabilities: Set<RuntimeCapability>

    public init(version: String, capabilities: Set<RuntimeCapability>) {
        self.version = version
        self.capabilities = capabilities
    }
}

/// Foundations of the per-user daemon. Supervision and the XPC listener arrive
/// in later issues; this slice binds every request to a caller identity,
/// verifies it, serializes execution, and proves the redacted receipt path
/// with fakes.
public struct DaemonBootstrap: Sendable {
    private let custodian: any SecretCustodian
    /// Receipt key for this daemon. Defaults to the process-wide key, so
    /// receipts correlate across instances within one process lifetime and are
    /// unlinkable across restarts. See ReceiptKeyStore.
    private let receiptKey: SymmetricKey
    private let dispatcher: SerializedDispatcher

    /// Default daemon. The verifier is the production one, which denies every
    /// call while audit-token verification is disabled, so an unconfigured
    /// daemon is closed rather than open.
    public init(custodian: any SecretCustodian) {
        self.init(
            custodian: custodian,
            verifier: ProductionCallerVerifier(),
            receiptKey: ReceiptKeyStore.processKey
        )
    }

    /// Injectable verifier, so tests exercise the caller boundary with fakes
    /// and a real verifier can be supplied once a release identity exists.
    public init(custodian: any SecretCustodian, verifier: any CallerVerifier) {
        self.init(
            custodian: custodian,
            verifier: verifier,
            receiptKey: ReceiptKeyStore.processKey
        )
    }

    /// Explicit-key initialiser, used by tests to prove the key factory is
    /// random. Deliberately not public: a caller must not choose the key.
    init(
        custodian: any SecretCustodian,
        verifier: any CallerVerifier = ProductionCallerVerifier(),
        receiptKey: SymmetricKey
    ) {
        self.custodian = custodian
        self.receiptKey = receiptKey
        self.dispatcher = SerializedDispatcher(verifier: verifier)
    }

    public func start() -> BootstrapReport {
        BootstrapReport(
            version: SecretBrokerVersion.current,
            capabilities: RuntimePolicy.capabilities
        )
    }

    /// The only caller-facing entry point. Every request is bound to a caller
    /// identity, verified, and serialized. There is deliberately no unverified
    /// public path: an operation a caller could reach without presenting an
    /// identity would make the production denial meaningless.
    public func dispatch(
        _ request: BrokeredRequest,
        from caller: CallerIdentity
    ) async -> DaemonOutcome {
        let outcome = await dispatcher.dispatch(BrokeredOperationKind(request), from: caller) {
            await execute(request).resultClass
        }
        switch outcome {
        case .denied(let reason):
            return .denied(reason)
        case .completed(let resultClass):
            return .completed(
                BrokeredReceipt(
                    requestDigest: digest(of: reference(in: request)),
                    resultClass: resultClass
                )
            )
        }
    }

    private func reference(in request: BrokeredRequest) -> SecretReference {
        switch request {
        case .availability(let reference):
            return reference
        }
    }

    /// Runs the operation itself. Private: reaching this without passing the
    /// caller check is exactly what must not be possible.
    private func execute(_ request: BrokeredRequest) async -> BrokeredReceipt {
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
    /// Keyed with the process key rather than hashed directly: the reference
    /// space is small and enumerable, so an unkeyed digest of a reference is
    /// recoverable by wordlist. Keying keeps receipts correlatable inside one
    /// process lifetime and meaningless outside it.
    func digest(of reference: SecretReference) -> String {
        let canonical = "\(reference.namespace)\u{1F}\(reference.name)"
        let code = HMAC<SHA256>.authenticationCode(
            for: Data(canonical.utf8),
            using: receiptKey
        )
        return code.map { String(format: "%02x", $0) }.joined()
    }
}
