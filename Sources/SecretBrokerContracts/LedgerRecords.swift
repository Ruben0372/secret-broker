import CryptoKit
import Foundation

/// Vocabulary and storage seam for the reservation ledger.
///
/// This lives in contracts rather than core because the storage seam has to be
/// visible to both the state machine (core) and a real store (adapters), and
/// the adapters dependency list is pinned to contracts alone. Putting the seam
/// here changes the dependency graph not at all. The alternative, admitting
/// core into the adapters allowlist, would mean relaxing a security pin so new
/// code fits, which is the most suspicious edit available and is not needed.
///
/// Nothing here can carry operation material. A row and a receipt name an
/// operation by id and bind it by digest; the bytes themselves never enter the
/// ledger, so a receipt proves an operation happened without being able to say
/// what it was.

// MARK: Errors

public enum LedgerError: Error, Sendable, Hashable {
    case invalidOperationID(String)
    case separatorInField(String)
    /// A stored row or receipt does not match its own integrity digest.
    case integrityMismatch(String)
    case storeUnavailable(String)
}

// MARK: Identity

/// Names one logical operation. Caller input, so validated at the boundary
/// rather than trusted downstream.
///
/// The bound on length is not cosmetic: this value is a primary key and is
/// echoed into every receipt, so an unbounded id is an unbounded write
/// amplification and an unbounded log line.
public struct LedgerOperationID: Sendable, Hashable, Codable, CustomStringConvertible {
    public static let maximumLength = 512

    public let value: String

    public var description: String { value }

    public init(_ value: String) throws {
        guard !value.isEmpty else {
            throw LedgerError.invalidOperationID("empty")
        }
        guard value.count <= Self.maximumLength else {
            throw LedgerError.invalidOperationID("longer than \(Self.maximumLength)")
        }
        let banned = CharacterSet.whitespacesAndNewlines.union(.controlCharacters)
        guard value.unicodeScalars.allSatisfy({ !banned.contains($0) }) else {
            throw LedgerError.invalidOperationID("contains whitespace or control characters")
        }
        self.value = value
    }
}

/// Binds an operation id to specific bytes.
///
/// This is what makes an altered replay detectable at all. Without it the
/// ledger is keyed on the id alone, and "same id, different bytes" reads as a
/// replay: the caller gets the earlier receipt for work that was never done.
public struct LedgerDigest: Sendable, Hashable, Codable, CustomStringConvertible {
    public let hex: String

    public var description: String { hex }

    public init(hex: String) {
        self.hex = hex
    }

    public static func over(_ bytes: [UInt8]) -> LedgerDigest {
        let preimage = Array(LedgerCanonicalization.operationDomain.utf8) + [0x00] + bytes
        let digest = SHA256.hash(data: Data(preimage))
        return LedgerDigest(hex: digest.map { String(format: "%02x", $0) }.joined())
    }
}

// MARK: States and dispositions

public enum LedgerState: String, Sendable, Hashable, Codable, CaseIterable {
    /// The at-most-once claim is held. The effect has NOT been dispatched.
    case reserved
    /// Consumption is persisted. The effect may be in flight or may have
    /// completed. This state is why a crash is survivable without a second send.
    case consumed
    case settledSucceeded
    case settledFailed
    /// Terminal for automatic execution. Requires reconciliation, and never
    /// reopens the idempotency key.
    case settledUnknown

    public var isTerminal: Bool {
        switch self {
        case .reserved, .consumed: return false
        case .settledSucceeded, .settledFailed, .settledUnknown: return true
        }
    }
}

public enum LedgerDisposition: String, Sendable, Hashable, Codable {
    case succeeded
    case failed
    case unknown
}

/// Closed set, so no free text can ride into a receipt. A reason is a code the
/// caller chose from a list, not a string it composed, which is the difference
/// between a redacted receipt and one that merely happens to be redacted today.
public enum LedgerReasonCode: String, Sendable, Hashable, Codable, CaseIterable {
    case effectRefused
    case effectOutcomeAmbiguous
    case effectThrew
    case settlementWriteFailed
    case reconciliationPending
}

public enum ReconciliationCause: String, Sendable, Hashable, Codable {
    /// Consumption is durable but no settlement is. The effect may or may not
    /// have happened, and nothing in the ledger can tell the difference.
    case consumedWithoutSettlement
    /// The caller reported an ambiguous outcome.
    case unknownSettlement
}

// MARK: Records

/// One ledger row. Identity and disposition only.
public struct LedgerRow: Sendable, Hashable, Codable, CustomStringConvertible {
    public let operationID: LedgerOperationID
    public let digest: LedgerDigest
    public let state: LedgerState
    public let sequence: UInt64
    public let reason: LedgerReasonCode?
    /// Digest over the canonical field list above. See the honesty note on
    /// `LedgerCanonicalization`: this detects corruption and naive tampering,
    /// not an attacker who recomputes it.
    public let integrity: String

    public var description: String {
        "LedgerRow(\(operationID.value) \(state.rawValue) seq \(sequence) digest \(digest.hex.prefix(12)))"
    }

    public init(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        state: LedgerState,
        sequence: UInt64,
        reason: LedgerReasonCode? = nil
    ) throws {
        self.operationID = operationID
        self.digest = digest
        self.state = state
        self.sequence = sequence
        self.reason = reason
        self.integrity = try LedgerCanonicalization.rowIntegrity(
            operationID: operationID,
            digest: digest,
            state: state,
            sequence: sequence,
            reason: reason
        )
    }

    /// Rebuilds a row read back from storage, preserving the stored integrity
    /// value rather than recomputing it. Recomputing on read would make every
    /// row verify against itself, which is a check that can never fail.
    public init(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        state: LedgerState,
        sequence: UInt64,
        reason: LedgerReasonCode?,
        storedIntegrity: String
    ) {
        self.operationID = operationID
        self.digest = digest
        self.state = state
        self.sequence = sequence
        self.reason = reason
        self.integrity = storedIntegrity
    }

    /// Throws when the stored integrity value does not describe these fields.
    public func verifyIntegrity() throws {
        let expected = try LedgerCanonicalization.rowIntegrity(
            operationID: operationID,
            digest: digest,
            state: state,
            sequence: sequence,
            reason: reason
        )
        guard expected == integrity else {
            throw LedgerError.integrityMismatch("row \(operationID.value)")
        }
    }

    public func advanced(to state: LedgerState, sequence: UInt64, reason: LedgerReasonCode? = nil) throws -> LedgerRow {
        try LedgerRow(
            operationID: operationID,
            digest: digest,
            state: state,
            sequence: sequence,
            reason: reason
        )
    }
}

/// Append-only, redacted evidence that an operation reached a terminal state.
///
/// Carries the operation digest, not the operation. AGENTS.md sanctions ids,
/// digests, result classes and redacted error codes in evidence, and that is
/// exactly and only what this holds.
public struct LedgerReceipt: Sendable, Hashable, Codable, CustomStringConvertible {
    public let operationID: LedgerOperationID
    public let digest: LedgerDigest
    public let disposition: LedgerDisposition
    public let reason: LedgerReasonCode?
    public let sequence: UInt64
    public let integrity: String

    public var description: String {
        "LedgerReceipt(\(operationID.value) \(disposition.rawValue) seq \(sequence) digest \(digest.hex.prefix(12)))"
    }

    public init(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        disposition: LedgerDisposition,
        reason: LedgerReasonCode?,
        sequence: UInt64
    ) throws {
        self.operationID = operationID
        self.digest = digest
        self.disposition = disposition
        self.reason = reason
        self.sequence = sequence
        self.integrity = try LedgerCanonicalization.receiptIntegrity(
            operationID: operationID,
            digest: digest,
            disposition: disposition,
            reason: reason,
            sequence: sequence
        )
    }

    public init(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        disposition: LedgerDisposition,
        reason: LedgerReasonCode?,
        sequence: UInt64,
        storedIntegrity: String
    ) {
        self.operationID = operationID
        self.digest = digest
        self.disposition = disposition
        self.reason = reason
        self.sequence = sequence
        self.integrity = storedIntegrity
    }

    public func verifyIntegrity() throws {
        let expected = try LedgerCanonicalization.receiptIntegrity(
            operationID: operationID,
            digest: digest,
            disposition: disposition,
            reason: reason,
            sequence: sequence
        )
        guard expected == integrity else {
            throw LedgerError.integrityMismatch("receipt \(operationID.value)")
        }
    }
}

/// Result of an attempt to claim an operation id.
public struct LedgerInsertion: Sendable, Hashable {
    /// True only for the caller whose insert created the row. Under concurrent
    /// callers exactly one may see true, which is where at-most-once is decided.
    public let created: Bool
    /// The row present in the store after the attempt, created or not.
    public let row: LedgerRow

    public init(created: Bool, row: LedgerRow) {
        self.created = created
        self.row = row
    }
}

// MARK: Storage seam

/// Durable storage for the ledger.
///
/// The at-most-once property is only as strong as the atomicity promised here,
/// so the promises are stated rather than implied:
///
/// - `createIfAbsent` is one atomic step. Under concurrent callers for the same
///   id, exactly one may return `created == true`. Deciding this in the caller
///   instead, by reading and then writing, is the classic double-send.
/// - `compareAndSet` writes only when the stored state equals `expected`, and
///   reports false without writing otherwise. A blind overwrite would let a
///   settlement clobber a state it never observed.
/// - `appendReceipt` is append-only. A second receipt for one operation id is
///   refused rather than replacing the first.
/// - A refused call writes nothing at all.
///
/// A store that breaks these promises breaks at-most-once, which is why the
/// state machine treats what it reads back as evidence to verify rather than as
/// truth.
public protocol LedgerStore: Sendable {
    /// Stable identity of this store, durable across restarts. Reservation
    /// tokens carry it so a token cannot be settled against a different store.
    func storeIdentity() throws -> String

    func createIfAbsent(_ row: LedgerRow) throws -> LedgerInsertion
    func compareAndSet(_ row: LedgerRow, expecting expected: LedgerState) throws -> Bool
    func row(for operationID: LedgerOperationID) throws -> LedgerRow?
    func appendReceipt(_ receipt: LedgerReceipt) throws
    func receipt(for operationID: LedgerOperationID) throws -> LedgerReceipt?

    /// Canonical, redacted dump of every row and receipt. Two uses: operator
    /// inspection, and proving that a refused step wrote nothing by comparing
    /// the snapshot either side of it.
    func snapshot() throws -> String
}

// MARK: Canonicalization

/// Deterministic bytes for the integrity digests.
///
/// Honest limit, stated here rather than discovered later: these are plain
/// SHA-256 digests, not keyed ones. They detect a partial write, a truncated
/// row, and a tamper that edits a field without recomputing the digest. They do
/// NOT stop an attacker who can write the database and recompute the digest,
/// because everything the digest is over is in the row.
///
/// Keying it would need a secret that survives a restart, which is a custody
/// question and not this issue's. Claiming tamper-proofing here would assert a
/// boundary that is not there, which is worse than not claiming it.
public enum LedgerCanonicalization {
    public static let operationDomain = "armel.broker.ledger.v1.operation"
    public static let rowDomain = "armel.broker.ledger.v1.row"
    public static let receiptDomain = "armel.broker.ledger.v1.receipt"

    /// Fields are joined with NUL, which cannot appear in any of them, so no
    /// two distinct field lists can produce one preimage. Without that the
    /// boundary between fields is guessable and two different rows could share
    /// an integrity value.
    static func canonicalBytes(domain: String, fields: [String]) throws -> [UInt8] {
        for field in fields where field.utf8.contains(0x00) {
            throw LedgerError.separatorInField(field)
        }
        var bytes = Array(domain.utf8)
        for field in fields {
            bytes.append(0x00)
            bytes += Array(field.utf8)
        }
        return bytes
    }

    static func digestHex(domain: String, fields: [String]) throws -> String {
        let bytes = try canonicalBytes(domain: domain, fields: fields)
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }

    static func rowIntegrity(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        state: LedgerState,
        sequence: UInt64,
        reason: LedgerReasonCode?
    ) throws -> String {
        try digestHex(
            domain: rowDomain,
            fields: [operationID.value, digest.hex, state.rawValue, String(sequence), reason?.rawValue ?? "-"]
        )
    }

    static func receiptIntegrity(
        operationID: LedgerOperationID,
        digest: LedgerDigest,
        disposition: LedgerDisposition,
        reason: LedgerReasonCode?,
        sequence: UInt64
    ) throws -> String {
        try digestHex(
            domain: receiptDomain,
            fields: [
                operationID.value, digest.hex, disposition.rawValue, reason?.rawValue ?? "-", String(sequence),
            ]
        )
    }
}
