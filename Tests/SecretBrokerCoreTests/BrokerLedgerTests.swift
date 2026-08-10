import Foundation
import SQLite3
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// Reservation, idempotency, and the redacted receipt ledger.
///
/// The acceptance bar has two halves and both are negative, so both have to be
/// hunted rather than asserted in passing:
///
/// 1. A logical operation is sent AT MOST ONCE.
/// 2. An altered replay NEVER reuses a receipt.
///
/// Every case below pairs its refusal with the legitimate path completing
/// (DISC-031). A ledger that refused everything would satisfy every must-fail
/// assertion here while being useless, and a ledger that never sent anything
/// would trivially satisfy at-most-once. Both halves are asserted, always.
///
/// Everything runs against a disposable database in a per-test temporary
/// directory. No real credentials, no production namespace, no external effect:
/// the "effect" is a counter, which is the only thing at-most-once is actually
/// about.

// MARK: Harness

/// Counts sends and records what was sent.
///
/// This is the whole acceptance instrument. At-most-once is a claim about this
/// counter, so it is deliberately the simplest possible thing that cannot lie:
/// a lock and an integer.
final class EffectRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var sent: [String] = []

    var sendCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sent.count
    }

    var sentOperations: [String] {
        lock.lock(); defer { lock.unlock() }
        return sent
    }

    func send(_ operationID: String) {
        lock.lock(); defer { lock.unlock() }
        sent.append(operationID)
    }
}

/// Wraps a store so a single write can be made to fail on demand.
///
/// A real crash is a write that never lands. Killing the test process would
/// prove the same thing and take the assertions down with it, so the fault is
/// injected at the seam instead: the effect has already happened, and the
/// settlement write does not arrive. What the ledger does next is the entire
/// question.
final class FaultInjectingStore: LedgerStore, @unchecked Sendable {
    enum Fault: Sendable, Hashable {
        case none
        case failNextSettlementWrite
        case failNextReceiptAppend
    }

    private let inner: any LedgerStore
    private let lock = NSLock()
    private var fault: Fault = .none
    private var fired = 0

    init(wrapping inner: any LedgerStore) {
        self.inner = inner
    }

    func arm(_ fault: Fault) {
        lock.lock(); defer { lock.unlock() }
        self.fault = fault
    }

    /// How many times an armed fault actually fired.
    ///
    /// Asserted by the caller, because a fault injector that quietly fails to
    /// inject is worse than no injector: the test still runs, still passes its
    /// count assertions, and proves nothing about the crash it claims to model.
    /// The first version of this file did exactly that, and only a disposition
    /// assertion caught it.
    var firedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return fired
    }

    /// Takes the fault only when it matches, so an unrelated write cannot
    /// disarm one that was aimed at a later step.
    private func takeFault(_ wanted: Fault) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard fault == wanted else { return false }
        fault = .none
        fired += 1
        return true
    }

    struct InjectedFailure: Error {}

    func storeIdentity() throws -> String { try inner.storeIdentity() }

    func createIfAbsent(_ row: LedgerRow) throws -> LedgerInsertion {
        try inner.createIfAbsent(row)
    }

    func compareAndSet(_ row: LedgerRow, expecting expected: LedgerState) throws -> Bool {
        // Only the settlement write, which is the transition out of consumed.
        // The consume write also passes through here and must not absorb it.
        if expected == .consumed, takeFault(.failNextSettlementWrite) {
            throw InjectedFailure()
        }
        return try inner.compareAndSet(row, expecting: expected)
    }

    func row(for operationID: LedgerOperationID) throws -> LedgerRow? {
        try inner.row(for: operationID)
    }

    func appendReceipt(_ receipt: LedgerReceipt) throws {
        if takeFault(.failNextReceiptAppend) {
            throw InjectedFailure()
        }
        try inner.appendReceipt(receipt)
    }

    func receipt(for operationID: LedgerOperationID) throws -> LedgerReceipt? {
        try inner.receipt(for: operationID)
    }

    func snapshot() throws -> String { try inner.snapshot() }
}

/// Edits the database behind the store's back.
///
/// Deliberately NOT an API on the adapter. A production type that offers to
/// corrupt its own ledger is a worse thing to ship than the test is to write,
/// and the threat being modelled is someone with write access to the file, not
/// someone holding a store instance. So the tamper opens its own connection and
/// issues the update an attacker would issue: change the disposition, leave the
/// integrity digest alone.
enum LedgerTamper {
    struct Failure: Error, CustomStringConvertible {
        let detail: String
        var description: String { "LedgerTamper(\(detail))" }
    }

    static func update(databaseAt path: String, sql: String, bindings: [String]) throws {
        var database: OpaquePointer?
        guard sqlite3_open_v2(path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let handle = database else {
            sqlite3_close_v2(database)
            throw Failure(detail: "cannot open \(path)")
        }
        defer { sqlite3_close_v2(handle) }

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let prepared = statement else {
            sqlite3_finalize(statement)
            throw Failure(detail: String(cString: sqlite3_errmsg(handle)))
        }
        defer { sqlite3_finalize(prepared) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (offset, binding) in bindings.enumerated() {
            sqlite3_bind_text(prepared, Int32(offset + 1), binding, -1, transient)
        }
        guard sqlite3_step(prepared) == SQLITE_DONE else {
            throw Failure(detail: String(cString: sqlite3_errmsg(handle)))
        }
        guard sqlite3_changes(handle) == 1 else {
            throw Failure(detail: "tamper changed \(sqlite3_changes(handle)) rows, expected exactly 1")
        }
    }

    static func setRowState(databaseAt path: String, operationID: String, state: String) throws {
        try update(
            databaseAt: path,
            sql: "UPDATE ledger_rows SET state = ? WHERE operation_id = ?;",
            bindings: [state, operationID]
        )
    }

    static func setReceiptDisposition(databaseAt path: String, operationID: String, disposition: String) throws {
        try update(
            databaseAt: path,
            sql: "UPDATE ledger_receipts SET disposition = ? WHERE operation_id = ?;",
            bindings: [disposition, operationID]
        )
    }
}

/// Every rendering of a payload that a surface could plausibly expose.
///
/// Carried over from the ARM-26 correction: matching one spelling of a value
/// is a guard that looks thorough and covers a fraction of the ground. The same
/// bytes are just as recoverable as a decimal array, a hex dump, or base64, so
/// the scan does the raw subsequence AND every textual rendering, each named so
/// a failure says WHICH spelling was found.
struct PayloadScanner {
    let payload: [UInt8]

    var renderings: [(name: String, value: String)] {
        [
            ("text", String(decoding: payload, as: UTF8.self)),
            ("decimal-spaced", "[" + payload.map(String.init).joined(separator: ", ") + "]"),
            ("decimal-tight", "[" + payload.map(String.init).joined(separator: ",") + "]"),
            ("hex-lower", payload.map { String(format: "%02x", $0) }.joined()),
            ("hex-upper", payload.map { String(format: "%02X", $0) }.joined()),
            ("base64", Data(payload).base64EncodedString()),
        ]
    }

    func findings(in surface: String, named label: String) -> [String] {
        var found: [String] = []
        if Self.contains(Array(surface.utf8), subsequence: payload) {
            found.append("\(label): raw byte sequence")
        }
        for rendering in renderings where surface.contains(rendering.value) {
            found.append("\(label): \(rendering.name)")
        }
        return found
    }

    static func contains(_ haystack: [UInt8], subsequence needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for start in 0...(haystack.count - needle.count)
        where Array(haystack[start..<(start + needle.count)]) == needle {
            return true
        }
        return false
    }
}

@Suite("Broker ledger, at-most-once and receipt integrity")
struct BrokerLedgerTests {
    /// Unmistakable in any haystack. If this turns up where it should not, the
    /// match is the finding, not a coincidence.
    static let payload = Array("ARM27-OPERATION-PAYLOAD-9c41d7ea52b8-DO-NOT-LEAK".utf8)
    static let alteredPayload = Array("ARM27-OPERATION-PAYLOAD-9c41d7ea52b8-ALTERED".utf8)

    /// Disposable directory per test. Removed by the caller, and residue is
    /// asserted rather than assumed.
    static func disposableDirectory(_ label: String = #function) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("arm27-disposable")
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    static func operationID(_ value: String = "op-1") throws -> LedgerOperationID {
        try LedgerOperationID(value)
    }

    /// Opens a SQLite ledger store in a disposable directory.
    static func makeStore(in directory: URL) throws -> SQLiteLedgerStore {
        try SQLiteLedgerStore(path: directory.appendingPathComponent("ledger.sqlite").path)
    }

    // MARK: Acceptance half one, at most once

    @Test("Concurrent reserve of one operation sends exactly once")
    func concurrentReserveSendsOnce() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let attempts = 32
        let outcomes = OutcomeCollector()
        DispatchQueue.concurrentPerform(iterations: attempts) { _ in
            let outcome = try? ledger.execute(
                operationID: identifier,
                bytes: Self.payload
            ) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
            outcomes.record(outcome)
        }

        #expect(
            effect.sendCount == 1,
            "the effect ran \(effect.sendCount) times under \(attempts) concurrent attempts; at-most-once is not held"
        )
        let performed = outcomes.all.filter { $0?.didPerformEffect == true }
        #expect(performed.count == 1, "\(performed.count) callers were told they performed the effect")

        // POSITIVE CONTROL: the losers are not errors, they are idempotent
        // replays carrying the same receipt. A ledger that simply refused all
        // 31 losers would satisfy the count above and be useless.
        let replays = outcomes.all.compactMap { $0?.receipt }
        #expect(replays.count == attempts, "only \(replays.count) of \(attempts) callers received a receipt")
        #expect(Set(replays).count == 1, "callers received \(Set(replays).count) distinct receipts for one operation")
    }

    @Test("A single reserve on a fresh operation completes")
    func singleReserveCompletes() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = BrokerLedger(store: try Self.makeStore(in: directory))
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let outcome = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }

        #expect(effect.sendCount == 1)
        #expect(outcome.didPerformEffect)
        #expect(outcome.receipt?.disposition == .succeeded)
    }

    @Test("Exact replay is idempotent and returns the same receipt")
    func exactReplayReturnsSameReceipt() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = BrokerLedger(store: try Self.makeStore(in: directory))
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let first = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        let second = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }

        #expect(effect.sendCount == 1, "the replay re-ran the effect")
        #expect(!second.didPerformEffect)
        let firstReceipt = try #require(first.receipt)
        let secondReceipt = try #require(second.receipt)
        #expect(firstReceipt == secondReceipt, "the replay returned a different receipt")

        // POSITIVE CONTROL: idempotency is keyed on the operation id, not on
        // the bytes. A DIFFERENT id carrying the SAME bytes is a different
        // logical operation and must get its own reservation and its own
        // receipt, or the ledger has silently become a content-addressed cache
        // that refuses legitimate repeat work.
        let other = try ledger.execute(operationID: try Self.operationID("op-2"), bytes: Self.payload) { _ in
            effect.send("op-2")
            return .succeeded
        }
        #expect(effect.sendCount == 2, "a distinct operation carrying the same bytes was suppressed")
        #expect(other.didPerformEffect)
        let otherReceipt = try #require(other.receipt)
        #expect(otherReceipt != firstReceipt)
    }

    // MARK: Acceptance half two, an altered replay never reuses a receipt

    @Test("Altered replay is a conflict and never returns the original receipt")
    func alteredReplayIsAConflict() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let original = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        let originalReceipt = try #require(original.receipt)
        let before = try store.snapshot()

        let altered = try ledger.execute(operationID: identifier, bytes: Self.alteredPayload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }

        #expect(effect.sendCount == 1, "the altered replay reached the effect")
        #expect(altered.didPerformEffect == false)
        #expect(
            altered.receipt == nil,
            "the altered replay was handed a receipt: \(String(describing: altered.receipt))"
        )
        guard case .conflict(let conflict) = altered.disposition else {
            Issue.record("altered replay disposition was \(altered.disposition), expected a conflict")
            return
        }
        #expect(conflict.storedDigest != conflict.presentedDigest)

        // VALIDATION BEFORE MUTATION: a refused step leaves the ledger untouched.
        #expect(try store.snapshot() == before, "the refused altered replay mutated the ledger")

        // POSITIVE CONTROL: the conflict did not poison the entry. The genuine
        // article still replays, and still yields the original receipt.
        let again = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1)
        let againReceipt = try #require(again.receipt)
        #expect(againReceipt == originalReceipt)
    }

    @Test("A conflict on a still-reserved operation also refuses, and sends nothing")
    func alteredReplayBeforeSettlementIsAConflict() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        // Claim without consuming, the pre-effect state.
        let reservation = try ledger.reserve(operationID: identifier, bytes: Self.payload)
        guard case .reserved = reservation else {
            Issue.record("expected a fresh reservation, got \(reservation)")
            return
        }
        let before = try store.snapshot()

        let altered = try ledger.execute(operationID: identifier, bytes: Self.alteredPayload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 0)
        #expect(altered.receipt == nil)
        guard case .conflict = altered.disposition else {
            Issue.record("expected a conflict, got \(altered.disposition)")
            return
        }
        #expect(try store.snapshot() == before, "the refused conflict mutated the ledger")

        // POSITIVE CONTROL: the held reservation is still usable by the bytes
        // it was made for.
        let resumed = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1)
        #expect(resumed.didPerformEffect)
    }

    // MARK: Crash and restart

    @Test("A pre-effect crash holds the reservation and sends nothing")
    func preEffectCrashHoldsReservation() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ledger.sqlite").path
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        // Claim, then lose the process before consuming. Nothing was sent.
        do {
            let ledger = BrokerLedger(store: try SQLiteLedgerStore(path: path))
            _ = try ledger.reserve(operationID: identifier, bytes: Self.payload)
        }
        #expect(effect.sendCount == 0)

        // Restart: a new ledger over the same file.
        let restarted = BrokerLedger(store: try SQLiteLedgerStore(path: path))
        let outcome = try restarted.reserve(operationID: identifier, bytes: Self.payload)
        guard case .alreadyReserved = outcome else {
            Issue.record("after a pre-effect crash the reservation was \(outcome), expected it still held")
            return
        }

        // Reconcilable: the legitimate path completes, exactly once.
        let completed = try restarted.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1)
        #expect(completed.didPerformEffect)
        #expect(completed.receipt?.disposition == .succeeded)
    }

    @Test("A post-effect crash is never lost and never auto-retried")
    func postEffectCrashRequiresReconciliation() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ledger.sqlite").path
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        // The effect happens, then the settlement write never lands.
        do {
            let faulted = FaultInjectingStore(wrapping: try SQLiteLedgerStore(path: path))
            let ledger = BrokerLedger(store: faulted)
            faulted.arm(.failNextSettlementWrite)
            _ = try? ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
            #expect(faulted.firedCount == 1, "the injected settlement failure never fired, so no crash was modelled")
        }
        #expect(effect.sendCount == 1, "the effect did not run, so this test proves nothing about losing it")

        // Restart. The operation is not lost: it is consumed with no settlement,
        // which is indistinguishable from an unknown outcome and must be
        // treated as one.
        let restarted = BrokerLedger(store: try SQLiteLedgerStore(path: path))
        let outcome = try restarted.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(
            effect.sendCount == 1,
            "the ledger auto-retried a consumed operation; that turns at-most-once into at-least-once"
        )
        guard case .reconciliationRequired(let cause) = outcome.disposition else {
            Issue.record("expected reconciliation, got \(outcome.disposition)")
            return
        }
        #expect(cause == .consumedWithoutSettlement)
        #expect(outcome.receipt == nil, "a consumed-without-settlement operation was handed a success receipt")

        // POSITIVE CONTROL: an operation that settles normally is not swept
        // into reconciliation.
        let clean = try restarted.execute(operationID: try Self.operationID("op-clean"), bytes: Self.payload) { _ in
            effect.send("op-clean")
            return .succeeded
        }
        #expect(effect.sendCount == 2)
        #expect(clean.receipt?.disposition == .succeeded)
    }

    @Test("Ledger state and receipts survive a restart")
    func stateSurvivesRestart() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ledger.sqlite").path
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let receipt: LedgerReceipt
        do {
            let ledger = BrokerLedger(store: try SQLiteLedgerStore(path: path))
            let outcome = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
                effect.send(identifier.value)
                return .succeeded
            }
            receipt = try #require(outcome.receipt)
        }

        let restarted = BrokerLedger(store: try SQLiteLedgerStore(path: path))
        let replay = try restarted.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1, "the restart re-ran a settled operation")
        let replayReceipt = try #require(replay.receipt)
        #expect(replayReceipt == receipt, "the receipt changed across a restart")

        // POSITIVE CONTROL: the restarted ledger is not simply refusing
        // everything it did not create.
        let fresh = try restarted.execute(operationID: try Self.operationID("op-fresh"), bytes: Self.payload) { _ in
            effect.send("op-fresh")
            return .succeeded
        }
        #expect(effect.sendCount == 2)
        #expect(fresh.didPerformEffect)
    }

    // MARK: Unknown is terminal

    @Test("An unknown settlement is terminal and does not reopen the key")
    func unknownSettlementIsTerminal() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let first = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .unknown(.effectOutcomeAmbiguous)
        }
        #expect(effect.sendCount == 1)
        guard case .reconciliationRequired(let cause) = first.disposition else {
            Issue.record("an unknown settlement produced \(first.disposition)")
            return
        }
        #expect(cause == .unknownSettlement)

        // The key does not reopen: a second identical attempt is refused, and
        // in particular it is NOT a fresh reservation.
        let second = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1, "an unknown terminal reopened the idempotency key and the effect ran twice")
        guard case .reconciliationRequired = second.disposition else {
            Issue.record("a settled-unknown operation produced \(second.disposition) on retry")
            return
        }
        #expect(second.receipt == nil, "an unknown operation was handed a success receipt")

        // POSITIVE CONTROL: unknown is recorded, not swallowed. The evidence
        // that reconciliation is needed is durable and readable.
        let recorded = try #require(try store.row(for: identifier))
        #expect(recorded.state == .settledUnknown)

        // POSITIVE CONTROL: the ledger still works for everything else.
        let other = try ledger.execute(operationID: try Self.operationID("op-other"), bytes: Self.payload) { _ in
            effect.send("op-other")
            return .succeeded
        }
        #expect(effect.sendCount == 2)
        #expect(other.didPerformEffect)
    }

    @Test("A thrown effect is unknown, not failed")
    func thrownEffectIsUnknown() throws {
        struct EffectExploded: Error {}
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        // A throw is ambiguous by construction: the effect may have half
        // happened. Classifying it as a definite failure would be a claim the
        // ledger is not entitled to make.
        _ = try? ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            throw EffectExploded()
        }
        let recorded = try #require(try store.row(for: identifier))
        #expect(
            recorded.state == .settledUnknown,
            "a thrown effect settled as \(recorded.state); a throw is ambiguous, not a definite failure"
        )
        #expect(effect.sendCount == 1)
    }

    @Test("A definite failure is terminal and does not reopen the key")
    func definiteFailureIsTerminal() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ledger = BrokerLedger(store: try Self.makeStore(in: directory))
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        let first = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .failed(.effectRefused)
        }
        #expect(first.receipt?.disposition == .failed)

        // The reservation IS the at-most-once key, so a definite failure does
        // not reopen it either. Retrying is a new logical operation with a new
        // id, which is the caller stating that it means to try again rather
        // than the ledger inferring it.
        let second = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1, "a failed terminal reopened the idempotency key")
        let firstReceipt = try #require(first.receipt)
        let secondReceipt = try #require(second.receipt)
        #expect(secondReceipt == firstReceipt)

        // POSITIVE CONTROL: a new id does proceed, so failure is not sticky
        // across the whole ledger.
        let retry = try ledger.execute(operationID: try Self.operationID("op-retry"), bytes: Self.payload) { _ in
            effect.send("op-retry")
            return .succeeded
        }
        #expect(effect.sendCount == 2)
        #expect(retry.didPerformEffect)
    }

    // MARK: Corruption fails closed

    @Test("A corrupted row is detected and never reads as absent")
    func corruptionFailsClosed() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ledger.sqlite").path
        let store = try SQLiteLedgerStore(path: path)
        let ledger = BrokerLedger(store: store)
        let effect = EffectRecorder()
        let identifier = try Self.operationID()

        _ = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(effect.sendCount == 1)

        // The edit an attacker wants: make a spent operation look unspent.
        try LedgerTamper.setRowState(
            databaseAt: path,
            operationID: identifier.value,
            state: LedgerState.reserved.rawValue
        )

        let outcome = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            effect.send(identifier.value)
            return .succeeded
        }
        #expect(
            effect.sendCount == 1,
            "a tampered row let the operation run a second time; corruption must fail closed, not reopen the key"
        )
        guard case .corrupted = outcome.disposition else {
            Issue.record("a tampered row produced \(outcome.disposition), expected a corruption refusal")
            return
        }
        #expect(outcome.receipt == nil)

        // POSITIVE CONTROL that the detector is not vacuous: an untampered
        // ledger of the same shape reads clean, so the refusal above is a
        // response to the tampering rather than to the read path itself.
        let cleanDirectory = try Self.disposableDirectory("clean")
        defer { try? FileManager.default.removeItem(at: cleanDirectory) }
        let cleanLedger = BrokerLedger(store: try Self.makeStore(in: cleanDirectory))
        let cleanEffect = EffectRecorder()
        _ = try cleanLedger.execute(operationID: identifier, bytes: Self.payload) { _ in
            cleanEffect.send(identifier.value)
            return .succeeded
        }
        let cleanReplay = try cleanLedger.execute(operationID: identifier, bytes: Self.payload) { _ in
            cleanEffect.send(identifier.value)
            return .succeeded
        }
        #expect(cleanEffect.sendCount == 1)
        #expect(cleanReplay.receipt?.disposition == .succeeded)
    }

    @Test("A tampered receipt is detected")
    func tamperedReceiptIsDetected() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ledger.sqlite").path
        let ledger = BrokerLedger(store: try SQLiteLedgerStore(path: path))
        let identifier = try Self.operationID()

        _ = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in .succeeded }
        try LedgerTamper.setReceiptDisposition(
            databaseAt: path,
            operationID: identifier.value,
            disposition: LedgerDisposition.failed.rawValue
        )

        let outcome = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in .succeeded }
        guard case .corrupted = outcome.disposition else {
            Issue.record("a tampered receipt produced \(outcome.disposition), expected a corruption refusal")
            return
        }
        #expect(outcome.receipt == nil, "a tampered receipt was handed back as evidence")
    }

    // MARK: Receipts carry no operation material

    @Test("No rendering of the payload reaches any receipt or ledger surface")
    func receiptsCarryNoPayload() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try Self.makeStore(in: directory)
        let ledger = BrokerLedger(store: store)
        let scanner = PayloadScanner(payload: Self.payload)
        let identifier = try Self.operationID()

        let outcome = try ledger.execute(operationID: identifier, bytes: Self.payload) { _ in
            .failed(.effectRefused)
        }
        let receipt = try #require(outcome.receipt)

        var conflictText = ""
        let altered = try ledger.execute(operationID: identifier, bytes: Self.alteredPayload) { _ in .succeeded }
        conflictText = String(describing: altered.disposition)

        var surfaces: [(String, String)] = [
            ("receipt", String(describing: receipt)),
            ("receipt-json", String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)),
            ("row", String(describing: try #require(try store.row(for: identifier)))),
            ("outcome", String(describing: outcome)),
            ("conflict", conflictText),
        ]
        surfaces.append(("store-snapshot", try store.snapshot()))
        surfaces.append(("database-bytes", try Self.databaseText(in: directory)))
        #expect(surfaces.count == 7, "expected seven surfaces, gathered \(surfaces.count)")

        var findings: [String] = []
        for (label, surface) in surfaces {
            findings += scanner.findings(in: surface, named: label)
        }
        #expect(findings.isEmpty, "the operation payload is recoverable: \(findings)")

        // POSITIVE CONTROLS: the scans ran against real, populated surfaces.
        #expect(receipt.disposition == .failed)
        #expect(!conflictText.isEmpty)
        #expect(try Self.databaseText(in: directory).contains(identifier.value), "the database surface read nothing")
    }

    @Test("The payload scan detects every rendering planted into every surface")
    func payloadScanIsNotVacuous() {
        let scanner = PayloadScanner(payload: Self.payload)
        let labels = [
            "receipt", "receipt-json", "row", "outcome", "conflict", "store-snapshot", "database-bytes",
        ]
        #expect(labels.count == 7)

        var undetected: [String] = []
        var checks = 0
        for label in labels {
            for rendering in scanner.renderings {
                let planted = "\(label)(operation: op-1, payload: \(rendering.value))"
                if scanner.findings(in: planted, named: label).isEmpty {
                    undetected.append("\(label)/\(rendering.name)")
                }
                checks += 1
            }
        }
        #expect(undetected.isEmpty, "the scan cannot see: \(undetected)")
        #expect(checks == 42, "expected 42 checks across 7 surfaces and 6 renderings, ran \(checks)")
    }

    /// Everything recoverable from the database file itself, so redaction is
    /// proven against the bytes on disk rather than against the accessors.
    static func databaseText(in directory: URL) throws -> String {
        var text = ""
        for entry in try FileManager.default.contentsOfDirectory(atPath: directory.path) {
            let data = try Data(contentsOf: directory.appendingPathComponent(entry))
            text += String(decoding: data, as: UTF8.self)
        }
        return text
    }

    // MARK: Boundary validation

    @Test("An operation id is validated before anything is written")
    func operationIDIsValidatedAtTheBoundary() throws {
        let rejected = ["", "   ", String(repeating: "x", count: 513), "op\u{0}id", "op\nid"]
        for value in rejected {
            #expect(throws: LedgerError.self, "an operation id of \(value.count) chars was accepted") {
                _ = try LedgerOperationID(value)
            }
        }
        // POSITIVE CONTROL: ordinary ids are accepted, so the validator is not
        // simply refusing everything.
        for value in ["op-1", "task.approval.7f3a", "a", String(repeating: "x", count: 512)] {
            #expect(throws: Never.self) { _ = try LedgerOperationID(value) }
        }
    }

    @Test("Cleanup leaves no residue in the disposable directory")
    func disposableStateIsRemovable() throws {
        let directory = try Self.disposableDirectory()
        let path = directory.appendingPathComponent("ledger.sqlite").path
        do {
            let ledger = BrokerLedger(store: try SQLiteLedgerStore(path: path))
            _ = try ledger.execute(operationID: try Self.operationID(), bytes: Self.payload) { _ in .succeeded }
        }
        #expect(FileManager.default.fileExists(atPath: path), "nothing was written, so removal proves nothing")

        try FileManager.default.removeItem(at: directory)
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        #expect(!FileManager.default.fileExists(atPath: path))
    }
}

/// Collects outcomes from concurrent callers.
final class OutcomeCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var outcomes: [ExecutionOutcome?] = []

    var all: [ExecutionOutcome?] {
        lock.lock(); defer { lock.unlock() }
        return outcomes
    }

    func record(_ outcome: ExecutionOutcome?) {
        lock.lock(); defer { lock.unlock() }
        outcomes.append(outcome)
    }
}
