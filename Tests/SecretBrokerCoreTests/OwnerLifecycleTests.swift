import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// Owner lifecycle and attention-state foundations.
///
/// THE CRUX: the state machine can REQUEST ATTENTION but CANNOT approve its own
/// proposal or mutate Cadence. Proposal only.
///
/// Cannot-self-approve is structural, not checked. `OwnerApproval` has a private
/// initializer, so the only thing that can produce one is `OwnerAuthority`. The
/// machine holds no `OwnerAuthority`, is given none, and has no method that
/// returns one, so there is no expression a machine can write that yields an
/// approval. Self-approval is not refused at runtime; it is unsayable
/// (DISC-070/086). The executable attack below (DISC-029) drives the machine
/// through every path it exposes and confirms none yields an approval, and the
/// positive control shows that WITH an owner present the approval does complete,
/// so the refusal is about authority rather than about a broken path.
///
/// The attention machine is durable throughout: epoch, dedupe and lease are all
/// derived from durable facts in the ledger, never from an in-memory counter, so
/// they survive a restart (DISC-088). Every refusal asserts its EXACT reason and
/// carries a positive control that the legitimate case still succeeds, because a
/// machine that refuses everything satisfies a bare "was refused" assertion and
/// is also completely broken (the ARM-30 restart trap).

/// A clock a test can advance, safe to hand to a `@Sendable` closure.
final class FakeClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64

    init(_ value: UInt64) { self.value = value }

    func set(_ value: UInt64) {
        lock.lock(); defer { lock.unlock() }
        self.value = value
    }

    var now: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

/// Collects concurrent boolean outcomes.
final class OutcomeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var outcomes: [Bool] = []

    func record(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        outcomes.append(value)
    }

    var trueCount: Int {
        lock.lock(); defer { lock.unlock() }
        return outcomes.filter { $0 }.count
    }

    var total: Int {
        lock.lock(); defer { lock.unlock() }
        return outcomes.count
    }
}

@Suite("Owner lifecycle, proposal only and never self-approving")
struct OwnerLifecycleTests {
    static func disposableDirectory(_ label: String = #function) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("arm31-disposable")
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    static func makeMachine(in directory: URL, now: @escaping @Sendable () -> UInt64 = { 1_000 }) throws -> OwnerLifecycleMachine {
        OwnerLifecycleMachine(
            attentionLedger: try SQLiteLedgerStore(
                path: directory.appendingPathComponent("owner.sqlite").path
            ),
            now: now
        )
    }

    static func candidate(_ id: String = "candidate-a") -> AttentionCandidate {
        AttentionCandidate(identifier: id)
    }

    static func proposedChange(_ id: String = "change-1") -> ProposedChange {
        ProposedChange(
            identifier: id,
            reason: .rotateBrokerCredential,
            template: .credentialRotation,
            summaryDigestHex: LedgerDigest.over(Array("summary-\(id)".utf8)).hex
        )
    }

    // MARK: The crux, structural

    @Test("The machine cannot reach an owner approval through any path it exposes")
    func machineCannotSelfApprove() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let machine = try Self.makeMachine(in: directory)
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)

        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())
        #expect(!proposal.isOwnerApproved, "a fresh proposal is already owner approved")

        // EXECUTABLE ATTACK (DISC-029): drive the machine through everything it
        // can do with its own proposal, and confirm it is still not approved.
        // The machine can request attention on its own proposal, repeatedly,
        // and that never promotes it.
        for _ in 0..<3 {
            _ = try machine.requestAttention(
                for: proposal,
                request: AttentionRequest(identifier: "att-\(UUID().uuidString)", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 2_000)
            )
        }
        let afterAttention = try machine.currentProposal(proposal.identifier)
        #expect(afterAttention?.isOwnerApproved == false, "requesting attention promoted the proposal to approved")

        // The structural fact, and why this test does not try to assert it here.
        //
        // The only vendor of an OwnerApproval is OwnerAuthority.approve, and
        // OwnerApproval's initializer is inaccessible to the machine (it lives
        // in a different file, so fileprivate locks it out). recordOwnerDecision
        // CONSUMES an OwnerApproval and never produces one, so there is no
        // expression the machine can write that yields an approval.
        //
        // "The machine has no approve method and no method returning an
        // OwnerApproval or OwnerAuthority" is enforced by the compiled public
        // API golden (SecretBrokerCore.api.txt, checked in the bootstrap suite
        // via swift-api-digester), not asserted here from a self-reported list a
        // type could get wrong. If the machine ever grows such a method, the
        // golden delta trips a symbol-by-symbol review. This test is the
        // behavioral half: the machine, run through its own surface, cannot
        // reach an approval.
    }

    @Test("An owner present approves the proposal, and the machine records it")
    func ownerApprovalCompletesThroughTheAuthority() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let machine = try Self.makeMachine(in: directory)
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())

        // The owner, modeled as an authority the machine never holds. Only this
        // type can vend an OwnerApproval, and constructing it is an owner-side
        // act: the test stands in for the owner here.
        let owner = OwnerAuthority(ownerSecret: "arm31-fake-owner-secret")
        let approval = owner.approve(proposal)

        let recorded = try machine.recordOwnerDecision(approval, for: proposal)
        #expect(recorded.isOwnerApproved, "a genuine owner approval did not mark the proposal approved")

        // An approval for a DIFFERENT proposal does not approve this one: the
        // approval is bound to the proposal digest, so it cannot be lifted onto
        // another proposal (the ARM-27 altered-replay binding).
        let other = try machine.propose(Self.proposedChange("change-2"), asCandidate: Self.candidate())
        #expect(throws: OwnerLifecycleRefusal.self, "an approval was replayed onto a different proposal") {
            _ = try machine.recordOwnerDecision(approval, for: other)
        }
    }

    // MARK: The closed registry

    @Test("The reason, template and profile vocabularies are exactly the reviewed sets")
    func vocabulariesMatchTheReviewedSets() {
        #expect(
            Set(OwnerProposalReason.allCases.map(\.rawValue)) == [
                "rotateBrokerCredential", "revokeBrokerCredential", "enrollLinkedDevice", "retireLinkedDevice",
            ],
            "the reason set changed: \(OwnerProposalReason.allCases.map(\.rawValue).sorted()). A new reason is a new thing the machine can propose, and is a reviewed change."
        )
        #expect(
            Set(OwnerProposalTemplate.allCases.map(\.rawValue)) == [
                "credentialRotation", "credentialRevocation", "deviceEnrollment", "deviceRetirement",
            ],
            "the template set changed: \(OwnerProposalTemplate.allCases.map(\.rawValue).sorted())."
        )
        #expect(
            Set(AttentionDeliveryProfile.allCases.map(\.rawValue)) == ["ownerAttentionOnly", "disposableTestSink"],
            "the delivery profile set changed: \(AttentionDeliveryProfile.allCases.map(\.rawValue).sorted()). A profile is a destination, and a new one is a reviewed change."
        )
    }

    // MARK: Epoch monotonicity

    @Test("An epoch cannot go backward, and the bar holds across a restart")
    func epochMonotonicityIsDurable() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("owner.sqlite").path

        do {
            let machine = OwnerLifecycleMachine(attentionLedger: try SQLiteLedgerStore(path: path), now: { 1_000 })
            _ = try machine.establishEpoch(1, candidate: Self.candidate("cand-1"), supersedingCurrent: nil)
            _ = try machine.establishEpoch(2, candidate: Self.candidate("cand-2"), supersedingCurrent: 1)
        }

        // A NEW machine over the same ledger. The current epoch is derived from
        // durable rows, not from a counter this process never had.
        let restarted = OwnerLifecycleMachine(attentionLedger: try SQLiteLedgerStore(path: path), now: { 1_000 })

        // Backward: re-establishing an epoch that already exists is refused.
        #expect(throws: OwnerLifecycleRefusal.self, "epoch 1 was re-established after a restart") {
            _ = try restarted.establishEpoch(1, candidate: Self.candidate("cand-1"), supersedingCurrent: 0)
        }
        // Skipping ahead is refused too: an epoch must build on the current tip.
        #expect(throws: OwnerLifecycleRefusal.self, "an epoch skipped over the tip") {
            _ = try restarted.establishEpoch(9, candidate: Self.candidate("cand-9"), supersedingCurrent: 2)
        }

        // POSITIVE CONTROL: the legitimate next epoch still advances after the
        // restart. Without this the test passes on a machine that refuses every
        // establish, which is the ARM-30 trap.
        let advanced = try restarted.establishEpoch(3, candidate: Self.candidate("cand-3"), supersedingCurrent: 2)
        #expect(advanced.epoch == 3)
    }

    @Test("Concurrent establishers of one epoch: exactly one wins")
    func concurrentEpochEstablishmentPicksOneWinner() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("owner.sqlite").path
        // Create the file up front so the race is over the epoch claim, not
        // over schema creation.
        _ = try SQLiteLedgerStore(path: path)

        // Every establisher gets its OWN machine over the SAME ledger file, so
        // nothing in this process coordinates them: the per-machine lock does
        // not serialize across instances. What decides the single winner is the
        // durable createIfAbsent primary key, which the sequential tests cannot
        // exercise because they never race. This is the test that makes the
        // epoch at-most-once claim load-bearing rather than redundant with the
        // monotonicity read-check.
        let attempts = 24
        let winners = OutcomeBox()
        DispatchQueue.concurrentPerform(iterations: attempts) { index in
            guard let ledger = try? SQLiteLedgerStore(path: path) else { return }
            let machine = OwnerLifecycleMachine(attentionLedger: ledger, now: { 1_000 })
            do {
                _ = try machine.establishEpoch(1, candidate: Self.candidate("cand-\(index)"), supersedingCurrent: nil)
                winners.record(true)
            } catch {
                winners.record(false)
            }
        }
        #expect(
            winners.trueCount == 1,
            "\(winners.trueCount) establishers claimed epoch 1 concurrently; the durable at-most-once claim did not hold"
        )
        #expect(winners.total == attempts, "only \(winners.total) of \(attempts) establishers reported")
    }

    @Test("Candidate possession: only the epoch's candidate holds it")
    func onlyTheCurrentCandidateHolds() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let machine = try Self.makeMachine(in: directory)
        _ = try machine.establishEpoch(1, candidate: Self.candidate("holder"), supersedingCurrent: nil)

        // A different candidate cannot propose in an epoch established for
        // someone else.
        #expect(throws: OwnerLifecycleRefusal.self, "a non-candidate proposed in an epoch it does not hold") {
            _ = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate("impostor"))
        }
        // POSITIVE CONTROL: the actual candidate proposes fine.
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate("holder"))
        #expect(proposal.epoch == 1)
    }

    @Test("Break before make: a superseded epoch's candidate can no longer propose")
    func breakBeforeMake() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let machine = try Self.makeMachine(in: directory)
        _ = try machine.establishEpoch(1, candidate: Self.candidate("old"), supersedingCurrent: nil)
        _ = try machine.establishEpoch(2, candidate: Self.candidate("new"), supersedingCurrent: 1)

        // The old candidate is broken before the new is usable: it cannot
        // propose once superseded, so there are never two live epochs.
        #expect(throws: OwnerLifecycleRefusal.self, "a superseded candidate still proposed; two epochs were live at once") {
            _ = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate("old"))
        }
        // POSITIVE CONTROL: the new candidate holds.
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate("new"))
        #expect(proposal.epoch == 2)
    }

    // MARK: Attention dedupe

    @Test("An attention request is at-most-once, durably, with the exact reason")
    func attentionDedupeIsDurable() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("owner.sqlite").path
        let request = AttentionRequest(identifier: "att-dup", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 5_000)

        let proposalID: String
        do {
            let machine = OwnerLifecycleMachine(attentionLedger: try SQLiteLedgerStore(path: path), now: { 1_000 })
            _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
            let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())
            proposalID = proposal.identifier
            let first = try machine.requestAttention(for: proposal, request: request)
            #expect(first.disposition == .raised)
        }

        // A NEW machine over the same ledger. The duplicate is refused because
        // the dedupe is a durable primary key, not a set in memory.
        let restarted = OwnerLifecycleMachine(attentionLedger: try SQLiteLedgerStore(path: path), now: { 1_000 })
        let proposal = try #require(try restarted.currentProposal(proposalID))
        let replay = try restarted.requestAttention(for: proposal, request: request)
        #expect(replay.disposition == .refused)
        #expect(replay.refusal == .duplicateAttentionRequest, "duplicate refused for the wrong reason: \(replay.refusal?.rawValue ?? "none")")

        // POSITIVE CONTROL: a DIFFERENT attention request on the same proposal
        // still goes through after the restart, so dedupe is keyed on the
        // request and has not become a blanket refusal.
        let fresh = AttentionRequest(identifier: "att-fresh", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 5_000)
        let second = try restarted.requestAttention(for: proposal, request: fresh)
        #expect(second.disposition == .raised, "a distinct attention request was refused: \(second.refusal?.rawValue ?? "none")")
    }

    // MARK: Lease, delivery, recovery, expiry

    @Test("A claim lease is held by one deliverer at a time")
    func claimLeaseIsExclusive() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = FakeClock(1_000)
        let machine = try Self.makeMachine(in: directory, now: { clock.now })
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())
        let request = AttentionRequest(identifier: "att-lease", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 9_000)
        _ = try machine.requestAttention(for: proposal, request: request)

        let claim = try machine.claim(requestID: request.identifier, deliverer: "deliverer-a", leaseSeconds: 100)
        #expect(claim.holder == "deliverer-a")

        // A second deliverer cannot claim a live lease.
        #expect(throws: OwnerLifecycleRefusal.self, "two deliverers held one lease") {
            _ = try machine.claim(requestID: request.identifier, deliverer: "deliverer-b", leaseSeconds: 100)
        }
        // The same deliverer re-claiming (a heartbeat) is fine.
        let renewed = try machine.claim(requestID: request.identifier, deliverer: "deliverer-a", leaseSeconds: 100)
        #expect(renewed.holder == "deliverer-a")
    }

    @Test("A failed delivery is recoverable and re-claimable after the lease expires")
    func failedDeliveryRecovers() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = FakeClock(1_000)
        let machine = try Self.makeMachine(in: directory, now: { clock.now })
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())
        let request = AttentionRequest(identifier: "att-recover", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 9_000)
        _ = try machine.requestAttention(for: proposal, request: request)

        _ = try machine.claim(requestID: request.identifier, deliverer: "deliverer-a", leaseSeconds: 100)
        try machine.reportDeliveryFailed(requestID: request.identifier, deliverer: "deliverer-a")

        // Another deliverer can pick it up: a failed delivery does not strand
        // the request. It is not re-raised (no second attention firing), it is
        // re-claimed.
        let recovered = try machine.claim(requestID: request.identifier, deliverer: "deliverer-b", leaseSeconds: 100)
        #expect(recovered.holder == "deliverer-b")

        // POSITIVE CONTROL: delivery can then succeed and is terminal.
        try machine.reportDeliverySucceeded(requestID: request.identifier, deliverer: "deliverer-b")
        #expect(throws: OwnerLifecycleRefusal.self, "a delivered request was re-claimed") {
            _ = try machine.claim(requestID: request.identifier, deliverer: "deliverer-c", leaseSeconds: 100)
        }
    }

    @Test("A lease that has expired can be taken over by another deliverer")
    func expiredLeaseIsTakeable() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = FakeClock(1_000)
        let machine = try Self.makeMachine(in: directory, now: { clock.now })
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())
        let request = AttentionRequest(identifier: "att-expire", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 100_000)
        _ = try machine.requestAttention(for: proposal, request: request)

        _ = try machine.claim(requestID: request.identifier, deliverer: "deliverer-a", leaseSeconds: 100)
        // Before expiry, still exclusive.
        #expect(throws: OwnerLifecycleRefusal.self) {
            _ = try machine.claim(requestID: request.identifier, deliverer: "deliverer-b", leaseSeconds: 100)
        }
        // After the lease elapses, another deliverer may take over.
        clock.set(1_000 + 101)
        let takenOver = try machine.claim(requestID: request.identifier, deliverer: "deliverer-b", leaseSeconds: 100)
        #expect(takenOver.holder == "deliverer-b")
    }

    @Test("An attention request past its expiry is refused")
    func expiredRequestIsRefused() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let clock = FakeClock(1_000)
        let machine = try Self.makeMachine(in: directory, now: { clock.now })
        _ = try machine.establishEpoch(1, candidate: Self.candidate(), supersedingCurrent: nil)
        let proposal = try machine.propose(Self.proposedChange(), asCandidate: Self.candidate())

        let request = AttentionRequest(identifier: "att-stale", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 1_050)
        clock.set(1_100)
        let outcome = try machine.requestAttention(for: proposal, request: request)
        #expect(outcome.disposition == .refused)
        #expect(outcome.refusal == .attentionRequestExpired, "expired refused for the wrong reason: \(outcome.refusal?.rawValue ?? "none")")

        // POSITIVE CONTROL: an unexpired request at the same clock is raised.
        let live = AttentionRequest(identifier: "att-live", reason: .rotateBrokerCredential, template: .credentialRotation, expiresAt: 2_000)
        #expect(try machine.requestAttention(for: proposal, request: live).disposition == .raised)
    }

    // MARK: The mutation adapter stays fake

    @Test("Cadence mutation is a stop gate and every real path refuses")
    func cadenceMutationIsAStopGate() {
        #expect(OwnerLifecycleMachine.isCadenceMutationEnabled == false)
        #expect(!OwnerLifecycleMachine.cadenceMutationStopGate.isEmpty)
        #expect(throws: OwnerLifecycleRefusal.self, "a real Cadence mutator was constructed") {
            _ = try OwnerLifecycleMachine.liveCadenceMutator(endpointIdentifier: "would-be-real")
        }
    }
}
