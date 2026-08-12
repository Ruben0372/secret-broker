import SecretBrokerContracts

/// Owner-lifecycle value types, the closed vocabularies, and the owner
/// authority.
///
/// WHY THE OWNER AUTHORITY LIVES HERE, NOT WITH THE MACHINE.
///
/// `OwnerApproval` has a `fileprivate` initializer, so only code in THIS file
/// can construct one, and the sole path is `OwnerAuthority.approve`. The state
/// machine lives in `OwnerLifecycle.swift`, a different file, so it cannot
/// construct an `OwnerApproval` at all: there is no expression it can write that
/// yields one. That file boundary is doing structural work, and moving these
/// types in with the machine would quietly undo it. This is the DISC-089 shape:
/// self-approval is not refused, it is unsayable.
///
/// The honest residual, stated because it is real. Within one module, nothing
/// at the type level stops a FUTURE edit of the machine from constructing an
/// `OwnerAuthority` (its init is public so the test, an external module, can
/// stand in for the owner, and same-module code therefore can too). What holds
/// today: `OwnerApproval` is unforgeable, so approval MUST route through
/// `OwnerAuthority.approve`; the machine constructs no authority; and the
/// machine's surface has no approve method, which the compiled-API golden
/// enforces. Same posture as ARM-30's `createOwnerGrant`, which refuses
/// unconditionally rather than being structurally impossible to ever implement.

// MARK: Closed vocabularies

/// Why the machine is proposing a change. Closed set, pinned as an exact
/// reviewed set by test. A new reason is a new thing the machine can propose.
public enum OwnerProposalReason: String, Sendable, Hashable, CaseIterable, Codable {
    case rotateBrokerCredential
    case revokeBrokerCredential
    case enrollLinkedDevice
    case retireLinkedDevice
}

/// The shape of the change. Closed, pinned by test.
public enum OwnerProposalTemplate: String, Sendable, Hashable, CaseIterable, Codable {
    case credentialRotation
    case credentialRevocation
    case deviceEnrollment
    case deviceRetirement
}

/// Where an attention request may be delivered. An enumerated destination,
/// never a string, so a caller cannot point attention somewhere new and a new
/// profile is a reviewed code change.
public enum AttentionDeliveryProfile: String, Sendable, Hashable, CaseIterable, Codable {
    case ownerAttentionOnly
    /// Reaches nothing. Exists for tests.
    case disposableTestSink
}

// MARK: Candidate and change

/// A party that may hold an epoch and propose within it.
public struct AttentionCandidate: Sendable, Hashable {
    public let identifier: String

    public init(identifier: String) {
        self.identifier = identifier
    }

    /// The durable binding an epoch row carries. Possession is proven by
    /// reproducing this digest, so a different candidate does not match.
    var bindingDigestHex: String {
        LedgerDigest.over(Array("arm31.candidate.\(identifier)".utf8)).hex
    }
}

/// A proposed change, before it becomes a proposal in an epoch.
public struct ProposedChange: Sendable, Hashable {
    public let identifier: String
    public let reason: OwnerProposalReason
    public let template: OwnerProposalTemplate
    public let summaryDigestHex: String

    public init(identifier: String, reason: OwnerProposalReason, template: OwnerProposalTemplate, summaryDigestHex: String) {
        self.identifier = identifier
        self.reason = reason
        self.template = template
        self.summaryDigestHex = summaryDigestHex
    }
}

/// A proposal the machine has emitted. Proposal only: nothing here says it is
/// authorized, and `isOwnerApproved` can become true only by pairing with a
/// genuine `OwnerApproval` whose digest matches.
public struct Proposal: Sendable, Hashable, CustomStringConvertible {
    public let identifier: String
    public let epoch: UInt64
    public let candidateBindingHex: String
    /// Binds the proposal's content. An approval carries this digest, so an
    /// approval cannot be lifted onto a different proposal.
    public let digest: String
    public let isOwnerApproved: Bool

    public var description: String {
        "Proposal(\(identifier) epoch \(epoch) approved \(isOwnerApproved) digest \(digest.prefix(12)))"
    }

    init(identifier: String, epoch: UInt64, candidateBindingHex: String, digest: String, isOwnerApproved: Bool) {
        self.identifier = identifier
        self.epoch = epoch
        self.candidateBindingHex = candidateBindingHex
        self.digest = digest
        self.isOwnerApproved = isOwnerApproved
    }

    static func digest(identifier: String, epoch: UInt64, change: ProposedChange) -> String {
        let fields = [
            identifier, String(epoch), change.reason.rawValue, change.template.rawValue, change.summaryDigestHex,
        ]
        var bytes = Array("arm31.proposal.v1".utf8)
        for field in fields {
            bytes.append(0x1F)
            bytes += Array(field.utf8)
        }
        return LedgerDigest.over(bytes).hex
    }

    func approved() -> Proposal {
        Proposal(
            identifier: identifier, epoch: epoch, candidateBindingHex: candidateBindingHex,
            digest: digest, isOwnerApproved: true
        )
    }
}

// MARK: Attention request and outcomes

public struct AttentionRequest: Sendable, Hashable {
    public let identifier: String
    public let reason: OwnerProposalReason
    public let template: OwnerProposalTemplate
    /// Absolute time the request stops being actionable.
    public let expiresAt: UInt64

    public init(identifier: String, reason: OwnerProposalReason, template: OwnerProposalTemplate, expiresAt: UInt64) {
        self.identifier = identifier
        self.reason = reason
        self.template = template
        self.expiresAt = expiresAt
    }

    var contentDigestHex: String {
        var bytes = Array("arm31.attention.v1".utf8)
        for field in [identifier, reason.rawValue, template.rawValue, String(expiresAt)] {
            bytes.append(0x1F)
            bytes += Array(field.utf8)
        }
        return LedgerDigest.over(bytes).hex
    }
}

public enum AttentionDisposition: String, Sendable, Hashable {
    case raised
    case refused
}

public struct AttentionOutcome: Sendable, Hashable {
    public let disposition: AttentionDisposition
    public let refusal: OwnerLifecycleRefusal?
}

public struct AttentionClaim: Sendable, Hashable {
    public let requestID: String
    public let holder: String
    public let leaseExpiresAt: UInt64
}

// MARK: The owner authority

/// Evidence that a proposal passed through owner approval. Read the Wave 1
/// limit below before reading that as "the owner acted": in Wave 1 it means
/// someone called `approve` through an authority, not that a verified owner did.
///
/// What is structurally true: an `OwnerApproval` cannot be CONSTRUCTED except
/// through `OwnerAuthority.approve`. The initializer is `fileprivate`, so
/// nothing outside this file can build one, and the only caller inside this
/// file is `approve`. The state machine lives in another file and has no way to
/// make an `OwnerApproval`, which is what makes self-approval unsayable rather
/// than merely refused. That property does hold, and it is the acceptance.
///
/// WAVE 1 LIMIT, stated because "unforgeable" would otherwise claim more than
/// the code supports. There is NO registered-owner concept in Core yet.
/// `OwnerAuthority.init(ownerSecret:)` is public and accepts ANY string, and
/// `recordOwnerDecision` verifies the proposal digest but does NOT verify
/// `ownerBindingHex` against any registered owner, because there is no owner
/// identity to verify against. So `OwnerAuthority(ownerSecret: "anything")
/// .approve(proposal)` yields an accepted approval, and in Wave 1 the test
/// stands in for the owner. `ownerBindingHex` is carried now so that a later
/// wave, which introduces owner identity, can bind it to a registered owner;
/// adding an owner check here first would be an approximate boundary with no
/// real owner behind it, which is the mistake ARM-30 refused. An `OwnerApproval`
/// therefore proves that approval was minted through an authority, not that the
/// owner is who a reader might assume.
public struct OwnerApproval: Sendable, Hashable, CustomStringConvertible {
    public let proposalDigest: String
    public let ownerBindingHex: String

    public var description: String {
        "OwnerApproval(proposal \(proposalDigest.prefix(12)) by owner \(ownerBindingHex.prefix(8)))"
    }

    fileprivate init(proposalDigest: String, ownerBindingHex: String) {
        self.proposalDigest = proposalDigest
        self.ownerBindingHex = ownerBindingHex
    }
}

/// Stands in for the owner. The state machine does not hold one, is given none,
/// and has no method that returns one. In production an authority originates at
/// the owner boundary; in the fake the test constructs one to stand in for the
/// owner, exactly as ARM-30 modeled owner grants as originating outside the
/// broker.
///
/// Wave 1: `init(ownerSecret:)` accepts any string and nothing verifies it,
/// because there is no registered owner yet. The secret is folded into
/// `ownerBindingHex` so a later wave can bind an approval to a real owner
/// identity; today it binds to whatever secret was passed. See the Wave 1 limit
/// on `OwnerApproval`.
public struct OwnerAuthority: Sendable {
    private let ownerBindingHex: String

    public init(ownerSecret: String) {
        self.ownerBindingHex = LedgerDigest.over(Array("arm31.owner.\(ownerSecret)".utf8)).hex
    }

    /// The sole vendor of an `OwnerApproval`. The approval is bound to this
    /// proposal's digest, so it cannot be replayed onto another proposal.
    public func approve(_ proposal: Proposal) -> OwnerApproval {
        OwnerApproval(proposalDigest: proposal.digest, ownerBindingHex: ownerBindingHex)
    }
}
