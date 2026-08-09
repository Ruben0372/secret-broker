import SecretBrokerContracts

public enum DispatchOutcome: Sendable, Hashable {
    case completed(BrokeredResultClass)
    case denied(CallerDenial)
}

/// Runs brokered operations one at a time, behind a caller check.
///
/// Actor isolation alone would not be enough. Swift actors are reentrant, so a
/// second call can enter while the first is suspended at an await, and a
/// brokered operation is expected to suspend. This holds an explicit lock
/// across the whole operation instead, so no two operations overlap even when
/// they suspend.
///
/// Serialization matters here beyond tidiness: one-use state and consumption
/// records are only meaningful if operations cannot interleave while deciding
/// whether something was already spent.
public actor SerializedDispatcher {
    private let verifier: any CallerVerifier
    private var isBusy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    public init(verifier: any CallerVerifier) {
        self.verifier = verifier
    }

    /// Verifies the caller, then runs `operationBody` with exclusive access.
    ///
    /// A denied caller never reaches the body. The body must not dispatch back
    /// into the same dispatcher: the lock is not reentrant and would deadlock.
    public func dispatch(
        _ operation: BrokeredOperationKind,
        from caller: CallerIdentity,
        _ operationBody: @Sendable () async -> BrokeredResultClass
    ) async -> DispatchOutcome {
        await acquire()
        defer { release() }

        switch await verifier.verify(caller, for: operation) {
        case .denied(let reason):
            return .denied(reason)
        case .allowed:
            return .completed(await operationBody())
        }
    }

    private func acquire() async {
        guard isBusy else {
            isBusy = true
            return
        }
        await withCheckedContinuation { continuation in
            waiting.append(continuation)
        }
    }

    private func release() {
        if waiting.isEmpty {
            isBusy = false
        } else {
            // Hand the lock straight to the next waiter rather than clearing
            // isBusy, so a newly arriving call cannot jump the queue.
            waiting.removeFirst().resume()
        }
    }
}
