import Foundation
import SecretBrokerContracts

/// The owner-lifecycle state machine. Proposal only.
///
/// ACCEPTANCE: it can REQUEST ATTENTION but cannot approve its own proposal or
/// mutate Cadence.
///
/// It cannot approve because it cannot construct an `OwnerApproval` (that type's
/// initializer lives in `Attention.swift` and is fileprivate, so this file has
/// no way to make one). `recordOwnerDecision` CONSUMES an approval supplied by
/// the owner and never produces one. It cannot mutate Cadence because it has no
/// Cadence-mutating method: the mutation adapter is a stop gate that refuses
/// while disabled.
///
/// Every durable fact lives in the ledger, never in an in-memory counter, so a
/// restart derives its state from the store rather than from a number this
/// process never had (DISC-088). The epoch is derived by walking the durable
/// epoch rows; dedupe and lease are durable primary keys.

/// Why an owner-lifecycle operation was refused. Typed and closed.
public enum OwnerLifecycleRefusal: String, Error, Sendable, Hashable, CaseIterable {
    case epochNotMonotonic
    case noEpochEstablished
    case notCurrentCandidate
    case unknownProposal
    case duplicateAttentionRequest
    case attentionRequestExpired
    case unknownAttentionRequest
    case leaseHeldByAnother
    case requestAlreadyDelivered
    case notLeaseHolder
    case approvalProposalMismatch
    case cadenceMutationDisabled
}

public final class OwnerLifecycleMachine: @unchecked Sendable {
    /// The mutation adapter stays fake. Flipping this is a reviewed change with
    /// a real Cadence client behind it, not a Boolean over code that exists.
    public static let isCadenceMutationEnabled = false

    public static let cadenceMutationStopGate = """
    Cadence mutation stays disabled until a reviewed Cadence client and an \
    owner-approved apply path exist. The machine proposes and requests \
    attention; it does not write to Cadence. An owner approval is consumed \
    from the owner, never produced here, and applying it is a later issue.
    """

    private let ledger: any LedgerStore
    private let now: @Sendable () -> UInt64
    private let lock = NSLock()

    public init(attentionLedger: any LedgerStore, now: @escaping @Sendable () -> UInt64) {
        self.ledger = attentionLedger
        self.now = now
    }

    // MARK: Stop gate

    public static func liveCadenceMutator(endpointIdentifier: String) throws -> OwnerLifecycleMachine {
        guard isCadenceMutationEnabled else {
            throw OwnerLifecycleRefusal.cadenceMutationDisabled
        }
        throw OwnerLifecycleRefusal.cadenceMutationDisabled
    }

    // MARK: Keys

    private static func epochKey(_ epoch: UInt64) throws -> LedgerOperationID {
        try LedgerOperationID("owner.epoch.\(epoch)")
    }

    private static func proposalKey(_ identifier: String) throws -> LedgerOperationID {
        try LedgerOperationID("owner.proposal.\(identifier)")
    }

    private static func approvalKey(_ proposalID: String) throws -> LedgerOperationID {
        try LedgerOperationID("owner.approval.\(proposalID)")
    }

    private static func attentionKey(_ requestID: String) throws -> LedgerOperationID {
        try LedgerOperationID("owner.attention.\(requestID)")
    }

    private static func leaseKey(_ requestID: String) throws -> LedgerOperationID {
        try LedgerOperationID("owner.lease.\(requestID)")
    }

    // MARK: Epoch

    /// The current epoch tip, derived by walking durable rows from the bottom.
    ///
    /// No in-memory counter: a fresh process finds the tip by asking the ledger
    /// which epoch rows exist. Bounded by the number of epochs ever established,
    /// which for this fake is small.
    private func currentEpoch() throws -> UInt64 {
        var epoch: UInt64 = 0
        while try ledger.row(for: try Self.epochKey(epoch + 1)) != nil {
            epoch += 1
        }
        return epoch
    }

    public struct EstablishedEpoch: Sendable, Hashable {
        public let epoch: UInt64
        public let candidate: AttentionCandidate
    }

    /// Establishes a new epoch on top of the current tip.
    ///
    /// Monotonic and durable. The caller states the epoch it means to supersede,
    /// which must match the durable tip, and the new epoch must be exactly one
    /// past it. A backward move re-establishes an existing row and is refused;
    /// a skip lands past the tip and is refused. Break-before-make falls out:
    /// once epoch e+1 exists, e is no longer the tip, so its candidate can no
    /// longer propose and two epochs are never live at once.
    @discardableResult
    public func establishEpoch(
        _ epoch: UInt64,
        candidate: AttentionCandidate,
        supersedingCurrent: UInt64?
    ) throws -> EstablishedEpoch {
        lock.lock(); defer { lock.unlock() }
        let tip = try currentEpoch()
        let expectedSuperseded: UInt64? = tip == 0 ? nil : tip
        guard supersedingCurrent == expectedSuperseded else {
            throw OwnerLifecycleRefusal.epochNotMonotonic
        }
        guard epoch == tip + 1 else {
            throw OwnerLifecycleRefusal.epochNotMonotonic
        }
        let row = try LedgerRow(
            operationID: try Self.epochKey(epoch),
            digest: LedgerDigest(hex: candidate.bindingDigestHex),
            state: .settledSucceeded,
            sequence: epoch
        )
        // The at-most-once claim on this epoch. If it already exists, this is a
        // backward move that slipped past the tip check under a race, and it is
        // refused rather than overwriting an established epoch.
        guard try ledger.createIfAbsent(row).created else {
            throw OwnerLifecycleRefusal.epochNotMonotonic
        }
        return EstablishedEpoch(epoch: epoch, candidate: candidate)
    }

    // MARK: Propose

    public func propose(_ change: ProposedChange, asCandidate candidate: AttentionCandidate) throws -> Proposal {
        lock.lock(); defer { lock.unlock() }
        let tip = try currentEpoch()
        guard tip >= 1 else { throw OwnerLifecycleRefusal.noEpochEstablished }

        // Possession, and break-before-make in one check: the tip epoch is bound
        // to exactly one candidate, and only that candidate reproduces the
        // binding. A superseded candidate is bound to an older epoch row, not
        // the tip, so it does not match here.
        let tipRow = try require(ledger.row(for: try Self.epochKey(tip)), .noEpochEstablished)
        guard tipRow.digest.hex == candidate.bindingDigestHex else {
            throw OwnerLifecycleRefusal.notCurrentCandidate
        }

        let digest = Proposal.digest(identifier: change.identifier, epoch: tip, change: change)
        let row = try LedgerRow(
            operationID: try Self.proposalKey(change.identifier),
            digest: LedgerDigest(hex: digest),
            state: .settledSucceeded,
            sequence: tip
        )
        _ = try ledger.createIfAbsent(row)
        return Proposal(
            identifier: change.identifier,
            epoch: tip,
            candidateBindingHex: candidate.bindingDigestHex,
            digest: digest,
            isOwnerApproved: try isApproved(change.identifier)
        )
    }

    public func currentProposal(_ identifier: String) throws -> Proposal? {
        lock.lock(); defer { lock.unlock() }
        guard let row = try ledger.row(for: try Self.proposalKey(identifier)) else { return nil }
        return Proposal(
            identifier: identifier,
            epoch: row.sequence,
            candidateBindingHex: "",
            digest: row.digest.hex,
            isOwnerApproved: try isApproved(identifier)
        )
    }

    private func isApproved(_ proposalID: String) throws -> Bool {
        try ledger.row(for: try Self.approvalKey(proposalID)) != nil
    }

    // MARK: Owner decision, consumed never produced

    /// Records an owner approval against its proposal. The approval is an input:
    /// this method cannot manufacture one, and the machine has no path to an
    /// `OwnerAuthority` that could. The approval is bound to the proposal digest,
    /// so an approval issued for one proposal cannot be recorded against another.
    public func recordOwnerDecision(_ approval: OwnerApproval, for proposal: Proposal) throws -> Proposal {
        lock.lock(); defer { lock.unlock() }
        guard approval.proposalDigest == proposal.digest else {
            throw OwnerLifecycleRefusal.approvalProposalMismatch
        }
        let row = try LedgerRow(
            operationID: try Self.approvalKey(proposal.identifier),
            digest: LedgerDigest.over(Array(approval.ownerBindingHex.utf8)),
            state: .settledSucceeded,
            sequence: proposal.epoch
        )
        _ = try ledger.createIfAbsent(row)
        return proposal.approved()
    }

    // MARK: Attention

    public func requestAttention(for proposal: Proposal, request: AttentionRequest) throws -> AttentionOutcome {
        lock.lock(); defer { lock.unlock() }

        // Expiry first: a request the owner could no longer act on in time is
        // not raised, so a stale request cannot sit in the queue looking live.
        guard now() < request.expiresAt else {
            return AttentionOutcome(disposition: .refused, refusal: .attentionRequestExpired)
        }

        // Durable dedupe. At-most-once on the request id, so a replay, including
        // one after a restart, does not raise attention twice.
        let row = try LedgerRow(
            operationID: try Self.attentionKey(request.identifier),
            digest: LedgerDigest(hex: request.contentDigestHex),
            state: .reserved,
            sequence: request.expiresAt
        )
        guard try ledger.createIfAbsent(row).created else {
            return AttentionOutcome(disposition: .refused, refusal: .duplicateAttentionRequest)
        }
        return AttentionOutcome(disposition: .raised, refusal: nil)
    }

    // MARK: Lease, delivery, recovery

    /// Claims a request for delivery under a lease.
    ///
    /// Exactly one holder while the lease is live. The same holder may renew.
    /// An expired lease may be taken over, and a failed delivery may be
    /// recovered. A delivered request is terminal and cannot be re-claimed.
    @discardableResult
    public func claim(requestID: String, deliverer: String, leaseSeconds: UInt64) throws -> AttentionClaim {
        lock.lock(); defer { lock.unlock() }
        guard try ledger.row(for: try Self.attentionKey(requestID)) != nil else {
            throw OwnerLifecycleRefusal.unknownAttentionRequest
        }
        let leaseKey = try Self.leaseKey(requestID)
        let holderDigest = LedgerDigest.over(Array(deliverer.utf8))
        let expiry = now() + leaseSeconds
        let newRow = try LedgerRow(operationID: leaseKey, digest: holderDigest, state: .reserved, sequence: expiry)

        guard let existing = try ledger.row(for: leaseKey) else {
            guard try ledger.createIfAbsent(newRow).created else {
                // Lost a race to create the lease; someone else holds it now.
                throw OwnerLifecycleRefusal.leaseHeldByAnother
            }
            return AttentionClaim(requestID: requestID, holder: deliverer, leaseExpiresAt: expiry)
        }

        switch existing.state {
        case .settledSucceeded:
            throw OwnerLifecycleRefusal.requestAlreadyDelivered
        case .settledFailed:
            // Recovery: a failed delivery is re-claimable by anyone.
            guard try ledger.compareAndSet(newRow, expecting: .settledFailed) else {
                throw OwnerLifecycleRefusal.leaseHeldByAnother
            }
        case .reserved:
            let sameHolder = existing.digest == holderDigest
            let expired = now() >= existing.sequence
            guard sameHolder || expired else {
                throw OwnerLifecycleRefusal.leaseHeldByAnother
            }
            guard try ledger.compareAndSet(newRow, expecting: .reserved) else {
                throw OwnerLifecycleRefusal.leaseHeldByAnother
            }
        default:
            throw OwnerLifecycleRefusal.leaseHeldByAnother
        }
        return AttentionClaim(requestID: requestID, holder: deliverer, leaseExpiresAt: expiry)
    }

    public func reportDeliveryFailed(requestID: String, deliverer: String) throws {
        try settleDelivery(requestID: requestID, deliverer: deliverer, to: .settledFailed)
    }

    public func reportDeliverySucceeded(requestID: String, deliverer: String) throws {
        try settleDelivery(requestID: requestID, deliverer: deliverer, to: .settledSucceeded)
    }

    private func settleDelivery(requestID: String, deliverer: String, to state: LedgerState) throws {
        lock.lock(); defer { lock.unlock() }
        let leaseKey = try Self.leaseKey(requestID)
        guard let existing = try ledger.row(for: leaseKey) else {
            throw OwnerLifecycleRefusal.unknownAttentionRequest
        }
        // Only the current lease holder may settle its own delivery.
        guard existing.state == .reserved, existing.digest == LedgerDigest.over(Array(deliverer.utf8)) else {
            throw OwnerLifecycleRefusal.notLeaseHolder
        }
        let settled = try LedgerRow(
            operationID: leaseKey,
            digest: existing.digest,
            state: state,
            sequence: existing.sequence
        )
        guard try ledger.compareAndSet(settled, expecting: .reserved) else {
            throw OwnerLifecycleRefusal.notLeaseHolder
        }
    }
}

/// Unwraps or throws a typed refusal, so a missing durable row fails closed
/// rather than trapping.
private func require<T>(_ value: T?, _ error: OwnerLifecycleRefusal) throws -> T {
    guard let value else { throw error }
    return value
}
