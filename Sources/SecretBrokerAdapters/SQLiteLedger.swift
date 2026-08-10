import Foundation
import SQLite3
import SecretBrokerContracts

/// Durable ledger storage on SQLite.
///
/// The at-most-once claim is a database primary key, not a lock. That is the
/// point of putting it here: a lock is lost when the holder dies, and every
/// interesting case in this issue is about a holder dying. A unique row keyed
/// on the operation id survives the crash, the restart, and a second process.
///
/// Every statement is parameterized. Operation ids are caller input and are
/// validated at the contract boundary, but they are still never concatenated
/// into SQL here, because a validator and a query builder should not have to
/// agree for the query to be safe.
///
/// This is a real adapter, not a fake, and it is named in the reviewed adapter
/// allowlist for that reason. It reaches no credential, no Keychain, and no
/// network: it opens one file at a caller-supplied path.
public final class SQLiteLedgerStore: LedgerStore, @unchecked Sendable {
    public struct StoreError: Error, Sendable, Hashable, CustomStringConvertible {
        public let operation: String
        public let code: Int32
        public let message: String

        public var description: String { "SQLiteLedgerStore(\(operation) failed, code \(code): \(message))" }
    }

    /// Tells SQLite to copy bound text rather than borrow it, which it must,
    /// since the Swift strings below do not outlive the bind call.
    private static let transientText = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private let handle: OpaquePointer
    private let lock = NSLock()

    public init(path: String) throws {
        var database: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let status = sqlite3_open_v2(path, &database, flags, nil)
        guard status == SQLITE_OK, let opened = database else {
            let message = database.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            sqlite3_close_v2(database)
            throw StoreError(operation: "open", code: status, message: message)
        }
        self.handle = opened

        // busy_timeout goes FIRST, before any statement that can take a lock.
        // Setting the journal mode and creating the schema are both writes, so
        // two openers racing at startup contend on them; with the timeout set
        // afterwards they contend with no timeout at all and one of them fails
        // the open outright. A concurrency test caught this intermittently, at
        // roughly three runs in ten.
        try execute("PRAGMA busy_timeout=5000;")

        // Durability settings are part of the guarantee, not tuning. WAL plus
        // FULL synchronous means a committed reservation is on disk before the
        // commit returns, which is what "persist consumption before dispatch"
        // requires to mean anything. Foreign keys are on so a receipt cannot
        // reference an operation with no row.
        try execute("PRAGMA journal_mode=WAL;")
        try execute("PRAGMA synchronous=FULL;")
        try execute("PRAGMA foreign_keys=ON;")
        try createSchema()
    }

    deinit {
        sqlite3_close_v2(handle)
    }

    // MARK: Schema

    private func createSchema() throws {
        try execute("""
        CREATE TABLE IF NOT EXISTS ledger_rows (
            operation_id TEXT PRIMARY KEY NOT NULL,
            digest TEXT NOT NULL,
            state TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            reason TEXT,
            integrity TEXT NOT NULL
        );
        """)
        // One receipt per operation id, enforced by the key rather than by
        // remembering to check. Append-only is a schema property here.
        try execute("""
        CREATE TABLE IF NOT EXISTS ledger_receipts (
            operation_id TEXT PRIMARY KEY NOT NULL
                REFERENCES ledger_rows(operation_id),
            digest TEXT NOT NULL,
            disposition TEXT NOT NULL,
            reason TEXT,
            sequence INTEGER NOT NULL,
            integrity TEXT NOT NULL
        );
        """)
        try execute("""
        CREATE TABLE IF NOT EXISTS ledger_identity (
            slot INTEGER PRIMARY KEY CHECK (slot = 1),
            value TEXT NOT NULL
        );
        """)
        // Durable so a reservation token stays valid across a restart. Minting
        // it per instance instead would mean a restarted store rejected its own
        // outstanding claims, which is the mistake ARM-26 made with generations.
        try execute(
            "INSERT OR IGNORE INTO ledger_identity(slot, value) VALUES (1, ?);",
            bindings: [UUID().uuidString]
        )
    }

    // MARK: LedgerStore

    public func storeIdentity() throws -> String {
        lock.lock(); defer { lock.unlock() }
        let rows = try query("SELECT value FROM ledger_identity WHERE slot = 1;", bindings: [], columns: 1)
        guard let value = rows.first?[0] else {
            throw StoreError(operation: "storeIdentity", code: SQLITE_ERROR, message: "identity row missing")
        }
        return value
    }

    /// One transaction. The insert either creates the row or does nothing, and
    /// the read that follows sees the committed result either way.
    ///
    /// BEGIN IMMEDIATE takes the write lock up front rather than upgrading
    /// halfway through. A deferred transaction that upgrades can fail with
    /// SQLITE_BUSY after it has already read, which is the shape where two
    /// callers both believe they are the creator.
    public func createIfAbsent(_ row: LedgerRow) throws -> LedgerInsertion {
        lock.lock(); defer { lock.unlock() }
        try execute("BEGIN IMMEDIATE;")
        do {
            try execute(
                """
                INSERT INTO ledger_rows(operation_id, digest, state, sequence, reason, integrity)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(operation_id) DO NOTHING;
                """,
                bindings: [
                    row.operationID.value, row.digest.hex, row.state.rawValue,
                    String(row.sequence), row.reason?.rawValue, row.integrity,
                ]
            )
            let created = sqlite3_changes(handle) == 1
            guard let stored = try readRow(row.operationID) else {
                throw StoreError(
                    operation: "createIfAbsent",
                    code: SQLITE_ERROR,
                    message: "row absent immediately after insert"
                )
            }
            try execute("COMMIT;")
            return LedgerInsertion(created: created, row: stored)
        } catch {
            try? execute("ROLLBACK;")
            throw error
        }
    }

    /// Writes only when the stored state is exactly `expected`. A blind update
    /// would let a settlement overwrite a state it never observed.
    public func compareAndSet(_ row: LedgerRow, expecting expected: LedgerState) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        try execute("BEGIN IMMEDIATE;")
        do {
            try execute(
                """
                UPDATE ledger_rows
                SET digest = ?, state = ?, sequence = ?, reason = ?, integrity = ?
                WHERE operation_id = ? AND state = ?;
                """,
                bindings: [
                    row.digest.hex, row.state.rawValue, String(row.sequence),
                    row.reason?.rawValue, row.integrity,
                    row.operationID.value, expected.rawValue,
                ]
            )
            let changed = sqlite3_changes(handle) == 1
            try execute("COMMIT;")
            return changed
        } catch {
            try? execute("ROLLBACK;")
            throw error
        }
    }

    public func row(for operationID: LedgerOperationID) throws -> LedgerRow? {
        lock.lock(); defer { lock.unlock() }
        return try readRow(operationID)
    }

    /// Append-only. A second receipt for one operation id is refused by the
    /// primary key, and the refusal is surfaced rather than swallowed.
    public func appendReceipt(_ receipt: LedgerReceipt) throws {
        lock.lock(); defer { lock.unlock() }
        try execute(
            """
            INSERT INTO ledger_receipts(operation_id, digest, disposition, reason, sequence, integrity)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            bindings: [
                receipt.operationID.value, receipt.digest.hex, receipt.disposition.rawValue,
                receipt.reason?.rawValue, String(receipt.sequence), receipt.integrity,
            ]
        )
    }

    public func receipt(for operationID: LedgerOperationID) throws -> LedgerReceipt? {
        lock.lock(); defer { lock.unlock() }
        let rows = try query(
            """
            SELECT digest, disposition, reason, sequence, integrity
            FROM ledger_receipts WHERE operation_id = ?;
            """,
            bindings: [operationID.value],
            columns: 5
        )
        guard let columns = rows.first else { return nil }
        guard let disposition = LedgerDisposition(rawValue: columns[1] ?? ""),
              let sequence = UInt64(columns[3] ?? ""),
              let digest = columns[0],
              let integrity = columns[4]
        else {
            throw StoreError(operation: "receipt", code: SQLITE_ERROR, message: "unreadable receipt columns")
        }
        return LedgerReceipt(
            operationID: operationID,
            digest: LedgerDigest(hex: digest),
            disposition: disposition,
            reason: columns[2].flatMap(LedgerReasonCode.init(rawValue:)),
            sequence: sequence,
            storedIntegrity: integrity
        )
    }

    public func snapshot() throws -> String {
        lock.lock(); defer { lock.unlock() }
        var lines: [String] = []
        for columns in try query(
            """
            SELECT operation_id, digest, state, sequence, reason, integrity
            FROM ledger_rows ORDER BY operation_id;
            """,
            bindings: [],
            columns: 6
        ) {
            lines.append("row " + columns.map { $0 ?? "-" }.joined(separator: " "))
        }
        for columns in try query(
            """
            SELECT operation_id, digest, disposition, reason, sequence, integrity
            FROM ledger_receipts ORDER BY operation_id;
            """,
            bindings: [],
            columns: 6
        ) {
            lines.append("receipt " + columns.map { $0 ?? "-" }.joined(separator: " "))
        }
        return lines.joined(separator: "\n")
    }

    // MARK: Statement plumbing

    private func readRow(_ operationID: LedgerOperationID) throws -> LedgerRow? {
        let rows = try query(
            """
            SELECT digest, state, sequence, reason, integrity
            FROM ledger_rows WHERE operation_id = ?;
            """,
            bindings: [operationID.value],
            columns: 5
        )
        guard let columns = rows.first else { return nil }
        guard let state = LedgerState(rawValue: columns[1] ?? ""),
              let sequence = UInt64(columns[2] ?? ""),
              let digest = columns[0],
              let integrity = columns[4]
        else {
            throw StoreError(operation: "readRow", code: SQLITE_ERROR, message: "unreadable row columns")
        }
        return LedgerRow(
            operationID: operationID,
            digest: LedgerDigest(hex: digest),
            state: state,
            sequence: sequence,
            reason: columns[3].flatMap(LedgerReasonCode.init(rawValue:)),
            storedIntegrity: integrity
        )
    }

    private func prepare(_ sql: String, bindings: [String?]) throws -> OpaquePointer {
        var statement: OpaquePointer?
        let status = sqlite3_prepare_v2(handle, sql, -1, &statement, nil)
        guard status == SQLITE_OK, let prepared = statement else {
            sqlite3_finalize(statement)
            throw StoreError(operation: "prepare", code: status, message: String(cString: sqlite3_errmsg(handle)))
        }
        for (offset, binding) in bindings.enumerated() {
            let index = Int32(offset + 1)
            let bindStatus: Int32
            if let binding {
                bindStatus = sqlite3_bind_text(prepared, index, binding, -1, Self.transientText)
            } else {
                bindStatus = sqlite3_bind_null(prepared, index)
            }
            guard bindStatus == SQLITE_OK else {
                sqlite3_finalize(prepared)
                throw StoreError(
                    operation: "bind",
                    code: bindStatus,
                    message: String(cString: sqlite3_errmsg(handle))
                )
            }
        }
        return prepared
    }

    private func execute(_ sql: String, bindings: [String?] = []) throws {
        let statement = try prepare(sql, bindings: bindings)
        defer { sqlite3_finalize(statement) }
        let status = sqlite3_step(statement)
        guard status == SQLITE_DONE || status == SQLITE_ROW else {
            throw StoreError(operation: "step", code: status, message: String(cString: sqlite3_errmsg(handle)))
        }
    }

    private func query(_ sql: String, bindings: [String?], columns: Int32) throws -> [[String?]] {
        let statement = try prepare(sql, bindings: bindings)
        defer { sqlite3_finalize(statement) }
        var results: [[String?]] = []
        while true {
            let status = sqlite3_step(statement)
            if status == SQLITE_DONE { break }
            guard status == SQLITE_ROW else {
                throw StoreError(operation: "step", code: status, message: String(cString: sqlite3_errmsg(handle)))
            }
            var row: [String?] = []
            for index in 0..<columns {
                if let text = sqlite3_column_text(statement, index) {
                    row.append(String(cString: text))
                } else {
                    row.append(nil)
                }
            }
            results.append(row)
        }
        return results
    }
}
