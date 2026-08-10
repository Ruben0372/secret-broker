import Foundation
import SecretBrokerContracts

/// The reservation ledger: what makes a logical operation happen at most once.
///
/// Two properties, both negative, both enforced here rather than asked of the
/// caller:
///
/// 1. A logical operation is sent AT MOST ONCE.
/// 2. An altered replay NEVER reuses a receipt.
///
/// The at-most-once guarantee lives in the store's atomic claim, not in any
/// lock held here. That distinction is the whole design. A lock does not
/// survive a crash; a durable row keyed on the operation id does, and the
/// crash and restart cases are exactly the ones a lock cannot answer.
///
/// The in-process gate below is an ergonomic convenience and is deliberately
/// NOT the safety mechanism. Removing it leaves at-most-once intact: concurrent
/// callers in one process would simply see an in-flight operation as needing
/// reconciliation instead of waiting for its receipt.
///
/// # Recovery
///
/// An operation lands in reconciliation when nothing in the ledger can say
/// whether its effect happened. There are exactly two ways in:
///
/// - `settledUnknown`: the caller reported an ambiguous outcome, or the effect
///   threw.
/// - `consumed` with no settlement: the process died between persisting
///   consumption and recording the result.
///
/// Both are terminal for automatic execution. The ledger will not retry them,
/// will not reopen the idempotency key, and will not hand back a receipt. That
/// is deliberate: every one of those would be a guess about whether a real
/// effect already happened, and being wrong means sending twice.
///
/// To find them, read the store for rows whose state is `consumed` or
/// `settledUnknown`. Both are visible in `LedgerStore.snapshot()`.
///
/// Resolving one is an operator action and needs evidence from OUTSIDE this
/// ledger: ask the system that would have received the effect whether it holds
/// the operation id and digest recorded on the row. Only that answer settles
/// the question.
///
/// Recording the operator's decision back into the ledger is deliberately NOT
/// implemented here. An API that writes a terminal state on request is an
/// auto-retry with a person's name on it unless it also carries the evidence
/// that justified the write, and designing that evidence is its own issue. If
/// the operation must be attempted again, it is attempted as a NEW logical
/// operation with a NEW operation id, which is the caller stating that intent
/// rather than the ledger inferring it.

/// A claim on an operation id. Minted only by a successful reservation, so a
/// caller cannot settle work it never reserved.
public struct LedgerReservation: Sendable, Hashable {
    public let row: LedgerRow
    /// Ties the claim to the store that granted it, so a token cannot be
    /// carried to a different ledger.
    public let storeIdentity: String

    public var operationID: LedgerOperationID { row.operationID }
    public var digest: LedgerDigest { row.digest }
}

/// Same id, different bytes. Carries the two digests and nothing else: handing
/// back the stored receipt here is precisely the failure this refuses.
public struct LedgerConflict: Sendable, Hashable, CustomStringConvertible {
    public let operationID: LedgerOperationID
    public let storedDigest: LedgerDigest
    public let presentedDigest: LedgerDigest

    public var description: String {
        "LedgerConflict(\(operationID.value) stored \(storedDigest.hex.prefix(12)) presented \(presentedDigest.hex.prefix(12)))"
    }
}

public enum ReservationOutcome: Sendable, Hashable {
    /// A fresh claim. This caller, and only this caller, created the row.
    case reserved(LedgerReservation)
    /// The claim is held from an earlier attempt and the effect was never
    /// dispatched, so resuming is safe.
    case alreadyReserved(LedgerReservation)
    /// Settled successfully. The stored receipt, unchanged.
    case replay(LedgerReceipt)
    /// Settled as a definite failure. Terminal, and it does not reopen the key.
    case terminated(LedgerReceipt)
    case reconciliationRequired(ReconciliationCause)
    case conflict(LedgerConflict)
    case corrupted(String)
}

/// What the caller reports about an effect it just attempted.
public enum EffectOutcome: Sendable, Hashable {
    case succeeded
    case failed(LedgerReasonCode)
    /// The caller cannot tell whether the effect happened. Preserved as its own
    /// lane rather than folded into failure, because treating an ambiguous
    /// result as a definite failure is how a retry becomes a second send.
    case unknown(LedgerReasonCode)
}

public enum ExecutionDisposition: Sendable, Hashable {
    case performed
    case replayed
    case conflict(LedgerConflict)
    case reconciliationRequired(ReconciliationCause)
    case corrupted(String)
}

public struct ExecutionOutcome: Sendable, Hashable {
    public let disposition: ExecutionDisposition
    /// Present only when this call is entitled to evidence of a definite
    /// outcome. Never present for a conflict, a corruption, or anything
    /// awaiting reconciliation.
    public let receipt: LedgerReceipt?
    /// Whether the effect closure actually ran during this call. Stated
    /// explicitly rather than inferred from the disposition, because an
    /// operation can both perform its effect and end up needing reconciliation.
    public let didPerformEffect: Bool
}

/// Serializes callers in one process, per operation id.
///
/// Without it, a caller racing the winner would read a consumed row with no
/// settlement, which is indistinguishable from a crash and correctly reads as
/// needing reconciliation. That is safe but unhelpful when the settling caller
/// is alive in the same process, so same-process callers wait and receive the
/// receipt. Across processes there is no such shortcut, and the ledger fails
/// closed rather than inventing a lease.
private final class OperationGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var inFlight: Set<String> = []

    func acquire(_ identifier: String) {
        condition.lock()
        while inFlight.contains(identifier) {
            condition.wait()
        }
        inFlight.insert(identifier)
        condition.unlock()
    }

    func release(_ identifier: String) {
        condition.lock()
        inFlight.remove(identifier)
        condition.broadcast()
        condition.unlock()
    }
}

public final class BrokerLedger: Sendable {
    private let store: any LedgerStore
    private let gate = OperationGate()

    public init(store: any LedgerStore) {
        self.store = store
    }

    // MARK: Primitives

    /// Claims an operation id, or explains why it cannot be claimed.
    ///
    /// Order matters and is the security content of this method:
    /// verify integrity, then bind the bytes, then classify the state. Any
    /// other order loses. Classifying first and comparing digests afterwards is
    /// how an altered replay collects the original receipt, because by the time
    /// the digest is examined the answer has already been decided.
    public func reserve(operationID: LedgerOperationID, bytes: [UInt8]) throws -> ReservationOutcome {
        let presented = LedgerDigest.over(bytes)
        let identity = try store.storeIdentity()
        let candidate = try LedgerRow(
            operationID: operationID,
            digest: presented,
            state: .reserved,
            sequence: 1
        )

        let insertion = try store.createIfAbsent(candidate)
        if insertion.created {
            // The store said it created this row. Check that the row it handed
            // back is the row it was given. A store is a seam anyone can
            // implement, so what it reports is evidence to check, not truth:
            // a claim granted over a DIFFERENT record is not a claim on this
            // operation at all.
            guard insertion.row == candidate else {
                return .corrupted(
                    "store reported creating \(operationID.value) but returned a different row"
                )
            }
            return .reserved(LedgerReservation(row: insertion.row, storeIdentity: identity))
        }

        let existing = insertion.row

        // Verify before trusting. A row that does not match its own integrity
        // digest is not evidence of anything, and in particular it is not
        // evidence that the operation is unclaimed. Reading it as absent would
        // reopen the key, which is the corruption failure that actually costs
        // something.
        do {
            try existing.verifyIntegrity()
        } catch {
            return .corrupted("row \(operationID.value) failed integrity verification")
        }

        // Bind before classifying.
        guard existing.digest == presented else {
            return .conflict(
                LedgerConflict(
                    operationID: operationID,
                    storedDigest: existing.digest,
                    presentedDigest: presented
                )
            )
        }

        switch existing.state {
        case .reserved:
            return .alreadyReserved(LedgerReservation(row: existing, storeIdentity: identity))
        case .consumed:
            // Consumption is durable, settlement is not. The effect may or may
            // not have happened and nothing here can tell the difference, so
            // this is the same answer as an explicit unknown.
            return .reconciliationRequired(.consumedWithoutSettlement)
        case .settledUnknown:
            return .reconciliationRequired(.unknownSettlement)
        case .settledSucceeded, .settledFailed:
            return try settledOutcome(for: existing, presented: presented)
        }
    }

    private func settledOutcome(for row: LedgerRow, presented: LedgerDigest) throws -> ReservationOutcome {
        guard let receipt = try store.receipt(for: row.operationID) else {
            return .corrupted("row \(row.operationID.value) is settled with no receipt")
        }
        do {
            try receipt.verifyIntegrity()
        } catch {
            return .corrupted("receipt \(row.operationID.value) failed integrity verification")
        }
        guard receipt.digest == presented else {
            return .conflict(
                LedgerConflict(
                    operationID: row.operationID,
                    storedDigest: receipt.digest,
                    presentedDigest: presented
                )
            )
        }
        // The row and its receipt are two records of one fact. If they
        // disagree, one of them was edited, and neither can be handed back as
        // evidence.
        let expected: LedgerDisposition = row.state == .settledSucceeded ? .succeeded : .failed
        guard receipt.disposition == expected else {
            return .corrupted("row \(row.operationID.value) and its receipt disagree about the outcome")
        }
        return row.state == .settledSucceeded ? .replay(receipt) : .terminated(receipt)
    }

    // MARK: The gated path

    /// Runs `effect` at most once for this operation id.
    ///
    /// Consumption is persisted BEFORE the effect is dispatched. Everything
    /// about crash survivability turns on that ordering: a crash before it
    /// means the effect definitely did not happen and the claim can be resumed,
    /// and a crash after it means the effect may have happened, which is
    /// reconciliation rather than a retry. Dispatching first and recording
    /// afterwards collapses those two cases into one and makes every crash look
    /// safe to retry.
    @discardableResult
    public func execute(
        operationID: LedgerOperationID,
        bytes: [UInt8],
        _ effect: (LedgerReservation) throws -> EffectOutcome
    ) throws -> ExecutionOutcome {
        gate.acquire(operationID.value)
        defer { gate.release(operationID.value) }

        let reservation: LedgerReservation
        switch try reserve(operationID: operationID, bytes: bytes) {
        case .reserved(let claim), .alreadyReserved(let claim):
            reservation = claim
        case .replay(let receipt), .terminated(let receipt):
            return ExecutionOutcome(disposition: .replayed, receipt: receipt, didPerformEffect: false)
        case .reconciliationRequired(let cause):
            return ExecutionOutcome(
                disposition: .reconciliationRequired(cause),
                receipt: nil,
                didPerformEffect: false
            )
        case .conflict(let conflict):
            return ExecutionOutcome(disposition: .conflict(conflict), receipt: nil, didPerformEffect: false)
        case .corrupted(let detail):
            return ExecutionOutcome(disposition: .corrupted(detail), receipt: nil, didPerformEffect: false)
        }

        let consumed = try reservation.row.advanced(to: .consumed, sequence: reservation.row.sequence + 1)
        guard try store.compareAndSet(consumed, expecting: .reserved) else {
            // Another holder advanced the row between the read and this write.
            // Reclassify once and stop. Looping here would be a retry loop
            // around an effect that may already have run.
            return try reclassifyWithoutRetrying(operationID: operationID, bytes: bytes)
        }
        // Read back before dispatching. This is the highest-value check in the
        // method: every crash-survivability claim rests on consumption being
        // durable BEFORE the effect runs, and a store that reports a write it
        // did not perform would make that claim false while everything still
        // looked correct. Nothing is dispatched until the consumed state is
        // actually there.
        try requireStored(consumed, step: "consume")

        let reported: EffectOutcome
        do {
            reported = try effect(reservation)
        } catch {
            // A throw is ambiguous by construction: the effect may have half
            // happened. Recording it as a definite failure would be a claim
            // this ledger is not entitled to make, and would invite a retry.
            _ = try? settle(consumed, as: .unknown, reason: .effectThrew)
            throw error
        }

        let disposition: LedgerDisposition
        let reason: LedgerReasonCode?
        switch reported {
        case .succeeded:
            disposition = .succeeded
            reason = nil
        case .failed(let code):
            disposition = .failed
            reason = code
        case .unknown(let code):
            disposition = .unknown
            reason = code
        }

        let receipt = try settle(consumed, as: disposition, reason: reason)

        if disposition == .unknown {
            // The receipt is written, because an unknown that leaves no trace
            // is indistinguishable from an operation that never ran. It is not
            // returned, because it is not evidence of a definite outcome.
            return ExecutionOutcome(
                disposition: .reconciliationRequired(.unknownSettlement),
                receipt: nil,
                didPerformEffect: true
            )
        }
        return ExecutionOutcome(disposition: .performed, receipt: receipt, didPerformEffect: true)
    }

    /// Advances a consumed row to its terminal state and appends the receipt.
    @discardableResult
    private func settle(
        _ consumed: LedgerRow,
        as disposition: LedgerDisposition,
        reason: LedgerReasonCode?
    ) throws -> LedgerReceipt {
        let state: LedgerState
        switch disposition {
        case .succeeded: state = .settledSucceeded
        case .failed: state = .settledFailed
        case .unknown: state = .settledUnknown
        }
        let settled = try consumed.advanced(
            to: state,
            sequence: consumed.sequence + 1,
            reason: reason
        )
        guard try store.compareAndSet(settled, expecting: .consumed) else {
            throw LedgerError.storeUnavailable("settlement lost the compare-and-set for \(consumed.operationID.value)")
        }
        try requireStored(settled, step: "settle")

        let receipt = try LedgerReceipt(
            operationID: settled.operationID,
            digest: settled.digest,
            disposition: disposition,
            reason: reason,
            sequence: settled.sequence
        )
        try store.appendReceipt(receipt)
        // A receipt that is not the one that was appended is not evidence of
        // this operation. Reading it back is what turns append-only from a
        // promise into something observed.
        guard let stored = try store.receipt(for: settled.operationID), stored == receipt else {
            throw LedgerError.storeViolatedContract(
                "receipt for \(settled.operationID.value) is absent or altered immediately after append"
            )
        }
        return receipt
    }

    /// Requires that the store actually holds `expected`.
    ///
    /// The seam is public API in an exported module, so any linker can supply a
    /// store. At-most-once is only ever as strong as the atomicity that seam
    /// promises, which means the promises have to be checked where checking is
    /// possible rather than assumed everywhere.
    private func requireStored(_ expected: LedgerRow, step: String) throws {
        guard let stored = try store.row(for: expected.operationID) else {
            throw LedgerError.storeViolatedContract(
                "\(step) reported success for \(expected.operationID.value) but the row is absent"
            )
        }
        guard stored == expected else {
            throw LedgerError.storeViolatedContract(
                "\(step) reported success for \(expected.operationID.value) but stored \(stored.state.rawValue) at sequence \(stored.sequence)"
            )
        }
    }

    private func reclassifyWithoutRetrying(
        operationID: LedgerOperationID,
        bytes: [UInt8]
    ) throws -> ExecutionOutcome {
        switch try reserve(operationID: operationID, bytes: bytes) {
        case .replay(let receipt), .terminated(let receipt):
            return ExecutionOutcome(disposition: .replayed, receipt: receipt, didPerformEffect: false)
        case .conflict(let conflict):
            return ExecutionOutcome(disposition: .conflict(conflict), receipt: nil, didPerformEffect: false)
        case .corrupted(let detail):
            return ExecutionOutcome(disposition: .corrupted(detail), receipt: nil, didPerformEffect: false)
        case .reconciliationRequired(let cause):
            return ExecutionOutcome(
                disposition: .reconciliationRequired(cause),
                receipt: nil,
                didPerformEffect: false
            )
        case .reserved, .alreadyReserved:
            // The row moved again. Refuse rather than take a second run at it.
            return ExecutionOutcome(
                disposition: .reconciliationRequired(.consumedWithoutSettlement),
                receipt: nil,
                didPerformEffect: false
            )
        }
    }
}
