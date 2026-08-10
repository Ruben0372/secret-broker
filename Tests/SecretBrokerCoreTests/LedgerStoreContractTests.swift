import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// What happens when the store lies.
///
/// The storage seam is public API in an exported module, so any linker can
/// supply a store, and at-most-once is only ever as strong as the atomicity
/// that seam promises. Stating the promises in a doc comment is not a control.
/// These tests are the control: for each way a store can break its contract,
/// either the ledger detects it, or this file says out loud that it cannot.
///
/// Two halves, and both are needed. The shipped SQLite store is checked against
/// the contract it claims to honour, and a deliberately treacherous store is
/// checked against the ledger's willingness to believe it.

/// A store that breaks exactly one promise on demand.
final class TreacherousStore: LedgerStore, @unchecked Sendable {
    enum Treachery: Sendable, Hashable {
        case none
        /// Reports creating the row, hands back a different one.
        case returnsForeignRowOnCreate
        /// Reports every claim as freshly created, while remaining honest
        /// about compare-and-set.
        case grantsEveryClaim
        /// Reports every claim as fresh AND writes on every compare-and-set
        /// regardless of the expected state. Both promises broken at once.
        case grantsEveryClaimAndBlindWrites
        /// Reports the consume write as done without performing it.
        case dropsConsumeWrite
        /// Reports the settlement write as done without performing it.
        case dropsSettlementWrite
        /// Stores a receipt other than the one it was handed.
        case replacesReceiptOnAppend
    }

    private let inner: any LedgerStore
    private let treachery: Treachery

    init(wrapping inner: any LedgerStore, doing treachery: Treachery) {
        self.inner = inner
        self.treachery = treachery
    }

    func storeIdentity() throws -> String { try inner.storeIdentity() }

    func createIfAbsent(_ row: LedgerRow) throws -> LedgerInsertion {
        let honest = try inner.createIfAbsent(row)
        switch treachery {
        case .returnsForeignRowOnCreate:
            let foreign = try LedgerRow(
                operationID: row.operationID,
                digest: LedgerDigest.over(Array("some other operation entirely".utf8)),
                state: .reserved,
                sequence: 1
            )
            return LedgerInsertion(created: true, row: foreign)
        case .grantsEveryClaim, .grantsEveryClaimAndBlindWrites:
            return LedgerInsertion(created: true, row: row)
        default:
            return honest
        }
    }

    func compareAndSet(_ row: LedgerRow, expecting expected: LedgerState) throws -> Bool {
        switch treachery {
        case .grantsEveryClaimAndBlindWrites:
            // Ignores the expected state entirely.
            _ = try inner.compareAndSet(row, expecting: expected)
            for state in LedgerState.allCases where state != expected {
                if try inner.compareAndSet(row, expecting: state) { break }
            }
            return true
        case .dropsConsumeWrite where expected == .reserved:
            return true
        case .dropsSettlementWrite where expected == .consumed:
            return true
        default:
            return try inner.compareAndSet(row, expecting: expected)
        }
    }

    func row(for operationID: LedgerOperationID) throws -> LedgerRow? {
        try inner.row(for: operationID)
    }

    func appendReceipt(_ receipt: LedgerReceipt) throws {
        if case .replacesReceiptOnAppend = treachery {
            try inner.appendReceipt(
                try LedgerReceipt(
                    operationID: receipt.operationID,
                    digest: receipt.digest,
                    disposition: .failed,
                    reason: .effectRefused,
                    sequence: receipt.sequence
                )
            )
            return
        }
        try inner.appendReceipt(receipt)
    }

    func receipt(for operationID: LedgerOperationID) throws -> LedgerReceipt? {
        try inner.receipt(for: operationID)
    }

    func snapshot() throws -> String { try inner.snapshot() }
}

@Suite("Ledger store contract, honoured and violated")
struct LedgerStoreContractTests {
    static let payload = Array("ARM27-STORE-CONTRACT-PAYLOAD".utf8)

    static func disposable(_ label: String = #function) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("arm27-store-contract")
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    static func store(in directory: URL) throws -> SQLiteLedgerStore {
        try SQLiteLedgerStore(path: directory.appendingPathComponent("ledger.sqlite").path)
    }

    static func identifier(_ value: String = "op-1") throws -> LedgerOperationID {
        try LedgerOperationID(value)
    }

    // MARK: The shipped store honours what the seam promises

    @Test("createIfAbsent creates once and reports the existing row after that")
    func createIfAbsentIsExclusive() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.store(in: directory)
        let identifier = try Self.identifier()
        let row = try LedgerRow(
            operationID: identifier,
            digest: LedgerDigest.over(Self.payload),
            state: .reserved,
            sequence: 1
        )

        let first = try store.createIfAbsent(row)
        #expect(first.created, "the first claim was not reported as created")
        #expect(first.row == row)

        let second = try store.createIfAbsent(row)
        #expect(!second.created, "a second claim on the same id was reported as created")
        #expect(second.row == row, "the second claim did not report the existing row")
    }

    @Test("compareAndSet refuses a state it did not observe, and writes nothing")
    func compareAndSetIsConditional() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.store(in: directory)
        let identifier = try Self.identifier()
        let reserved = try LedgerRow(
            operationID: identifier,
            digest: LedgerDigest.over(Self.payload),
            state: .reserved,
            sequence: 1
        )
        _ = try store.createIfAbsent(reserved)
        let before = try store.snapshot()

        let settled = try reserved.advanced(to: .settledSucceeded, sequence: 3)
        #expect(
            try store.compareAndSet(settled, expecting: .consumed) == false,
            "a compare-and-set against an unobserved state was accepted"
        )
        #expect(try store.snapshot() == before, "the refused compare-and-set still wrote")

        // POSITIVE CONTROL: the matching transition is accepted, so the refusal
        // above is conditional rather than a store that writes nothing.
        let consumed = try reserved.advanced(to: .consumed, sequence: 2)
        #expect(try store.compareAndSet(consumed, expecting: .reserved))
        #expect(try #require(try store.row(for: identifier)) == consumed)
    }

    @Test("appendReceipt refuses a second receipt for one operation")
    func appendReceiptIsAppendOnly() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.store(in: directory)
        let identifier = try Self.identifier()
        let digest = LedgerDigest.over(Self.payload)
        _ = try store.createIfAbsent(
            try LedgerRow(operationID: identifier, digest: digest, state: .settledSucceeded, sequence: 3)
        )

        let receipt = try LedgerReceipt(
            operationID: identifier,
            digest: digest,
            disposition: .succeeded,
            reason: nil,
            sequence: 3
        )
        try store.appendReceipt(receipt)
        let before = try store.snapshot()

        #expect(throws: (any Error).self, "a second receipt for one operation was accepted") {
            try store.appendReceipt(
                try LedgerReceipt(
                    operationID: identifier,
                    digest: digest,
                    disposition: .failed,
                    reason: .effectRefused,
                    sequence: 4
                )
            )
        }
        #expect(try store.snapshot() == before, "the refused append still changed the ledger")
        #expect(try #require(try store.receipt(for: identifier)) == receipt, "the original receipt was replaced")
    }

    // MARK: A store that lies is detected, or the limit is named

    @Test("A store that returns a foreign row on create is detected before any effect")
    func foreignRowOnCreateIsDetected() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let effect = EffectRecorder()
        let ledger = BrokerLedger(
            store: TreacherousStore(wrapping: try Self.store(in: directory), doing: .returnsForeignRowOnCreate)
        )

        let outcome = try ledger.execute(operationID: try Self.identifier(), bytes: Self.payload) { _ in
            effect.send("op-1")
            return .succeeded
        }
        guard case .corrupted = outcome.disposition else {
            Issue.record("a foreign row on create produced \(outcome.disposition)")
            return
        }
        #expect(effect.sendCount == 0, "the effect ran against a claim the store never actually granted")
    }

    @Test("A dropped consume write is detected before the effect is dispatched")
    func droppedConsumeWriteIsDetected() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let effect = EffectRecorder()
        let store = try Self.store(in: directory)
        let ledger = BrokerLedger(store: TreacherousStore(wrapping: store, doing: .dropsConsumeWrite))
        let identifier = try Self.identifier()

        #expect(throws: LedgerError.self, "a store that dropped the consume write was believed") {
            _ = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
        }
        // This is the one that matters most. Every crash-survivability claim
        // rests on consumption being durable BEFORE dispatch, so a store that
        // reports a write it did not perform must stop the operation rather
        // than let it proceed on a false record.
        #expect(effect.sendCount == 0, "the effect was dispatched on a consumption that was never stored")
        #expect(try #require(try store.row(for: identifier)).state == .reserved)

        // POSITIVE CONTROL: an honest store over the same file completes.
        let honest = BrokerLedger(store: store)
        let outcome = try honest.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1)
        #expect(outcome.receipt?.disposition == .succeeded)
    }

    @Test("A dropped settlement write is detected and does not become a success")
    func droppedSettlementWriteIsDetected() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let effect = EffectRecorder()
        let store = try Self.store(in: directory)
        let ledger = BrokerLedger(store: TreacherousStore(wrapping: store, doing: .dropsSettlementWrite))
        let identifier = try Self.identifier()

        #expect(throws: LedgerError.self) {
            _ = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
        }
        #expect(effect.sendCount == 1)
        #expect(
            try #require(try store.row(for: identifier)).state == .consumed,
            "a dropped settlement left a state other than consumed"
        )

        // The operation is not lost and not retried: an honest ledger over the
        // same file reads it as needing reconciliation.
        let honest = BrokerLedger(store: store)
        let outcome = try honest.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1, "the operation was retried after a dropped settlement")
        guard case .reconciliationRequired(let cause) = outcome.disposition else {
            Issue.record("expected reconciliation, got \(outcome.disposition)")
            return
        }
        #expect(cause == .consumedWithoutSettlement)
    }

    @Test("A store that replaces the receipt on append is detected")
    func replacedReceiptIsDetected() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = BrokerLedger(
            store: TreacherousStore(wrapping: try Self.store(in: directory), doing: .replacesReceiptOnAppend)
        )
        #expect(throws: LedgerError.self, "a substituted receipt was accepted as evidence") {
            _ = try ledger.execute(operationID: try Self.identifier(), bytes: Self.payload) { _ in .succeeded }
        }
    }

    // MARK: The boundary of what the ledger can defend

    @Test("At-most-once survives a store that lies about exclusivity alone")
    func atMostOnceSurvivesAFalselyGrantedClaim() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let effect = EffectRecorder()
        let ledger = BrokerLedger(
            store: TreacherousStore(wrapping: try Self.store(in: directory), doing: .grantsEveryClaim)
        )
        let identifier = try Self.identifier()

        for _ in 0..<5 {
            _ = try? ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
        }

        // The claim was granted five times and the effect still ran once. The
        // compare-and-set is what holds the line: a second caller cannot move a
        // row out of a state it is no longer in, whatever the claim said.
        #expect(
            effect.sendCount == 1,
            "the effect ran \(effect.sendCount) times; a falsely granted claim should still be stopped by the compare-and-set"
        )
    }

    /// The residual, asserted rather than described.
    ///
    /// A store that breaks BOTH the exclusive claim and the conditional write
    /// defeats at-most-once, and the ledger cannot detect it: every record it
    /// reads back is exactly the record it wrote, because the store performed
    /// the write it was asked for. It simply also performed one it was not.
    ///
    /// This test asserts the failure so the limit lives in the suite rather
    /// than in prose that can drift away from the code. If a later change makes
    /// this case survivable, this test fails, and that failure is good news
    /// that should be read carefully rather than deleted.
    @Test("A store that breaks both promises defeats at-most-once, and this is known")
    func atMostOnceCannotSurviveAFullyDishonestStore() throws {
        let directory = try Self.disposable()
        defer { try? FileManager.default.removeItem(at: directory) }
        let effect = EffectRecorder()
        let ledger = BrokerLedger(
            store: TreacherousStore(
                wrapping: try Self.store(in: directory),
                doing: .grantsEveryClaimAndBlindWrites
            )
        )
        let identifier = try Self.identifier()

        for _ in 0..<3 {
            _ = try? ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
        }

        #expect(
            effect.sendCount > 1,
            """
            The effect ran \(effect.sendCount) times. This test EXPECTS at-most-once to fail here, because a \
            store that both grants every claim and writes unconditionally leaves the ledger nothing to check \
            against: every read-back matches what was written. If this now passes at-most-once, the defence \
            improved and this expectation is stale. Work out which before changing it.
            """
        )
    }
}
