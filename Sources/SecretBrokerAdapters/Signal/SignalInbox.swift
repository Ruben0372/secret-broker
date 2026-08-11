import Foundation
import SecretBrokerContracts

/// Fake Signal ingress.
///
/// Decides what an arriving message is permitted to mean, and the answer is
/// only ever evidence, a stop, or a refusal. There is no path from here to an
/// authorizing act, and no type in this module can express one.
///
/// # Attention escalation
///
/// A STOP is a fail-safe signal, not an instruction the broker evaluates. What
/// happens on receipt, in order:
///
/// 1. The message is deduplicated durably, so a stop already acted on does not
///    re-fire and a replayed one does not either.
/// 2. The stop is recognised BEFORE any trust check. Sender pinning, safety
///    number and attachments are all evidence concerns; none of them may
///    suppress a stop. A stop from a sender whose key just changed is exactly
///    the case where stopping matters most.
/// 3. A stop receipt is issued under the stop domain tag, which is not the
///    evidence tag, so the two cannot be confused downstream.
/// 4. The stop is returned to the caller as `.stop`. It does not authorize
///    anything, cannot be promoted, and carries no reference to act on. The
///    only thing a caller can do with it is halt.
///
/// What deliberately does NOT escalate: an outage. A transport that cannot be
/// reached produces no message, and no message is not a stop. Treating silence
/// as a stop would make every network blip an incident, and treating it as
/// permission would be worse. It is refused with the reason named, and
/// escalation is the caller's decision on a signal it can see.
///
/// Real linkage stays disabled. This talks to nothing.
public final class SignalInbox: @unchecked Sendable {
    /// Flipped only when a reviewed linked-device design exists. Until then
    /// every real path refuses.
    public static let isRealLinkageEnabled = false

    public static let realLinkageGate = """
    Real Signal device linkage stays disabled until a reviewed linked-device \
    design exists. Linking a device binds this broker to an account and a real \
    conversation, and claiming that binding without the design would assert a \
    boundary that is not there. While it is disabled the fake ingress is the \
    only path that works, and it reaches no network and no account.
    """

    private let pinnedSenders: [String: SignalSender]
    private let dedupeStore: any LedgerStore
    private let lock = NSLock()
    private var isTransportAvailable = true

    public init(pinnedSenders: [SignalSender], dedupeStore: any LedgerStore) {
        self.pinnedSenders = Dictionary(
            uniqueKeysWithValues: pinnedSenders.map { ($0.serviceIdentifier, $0) }
        )
        self.dedupeStore = dedupeStore
    }

    /// The production entry point, which refuses while linkage is disabled.
    public static func linkedDeviceInbox(accountIdentifier: String) throws -> SignalInbox {
        guard isRealLinkageEnabled else {
            throw SignalRefusal.realLinkageDisabled
        }
        // Unreachable while the flag is false, and deliberately not written as
        // a real linkage path: enabling it is a reviewed change, not a matter
        // of flipping a Boolean over code that already exists.
        throw SignalRefusal.realLinkageDisabled
    }

    public func setTransportAvailable(_ available: Bool) {
        lock.lock(); defer { lock.unlock() }
        isTransportAvailable = available
    }

    private var transportAvailable: Bool {
        lock.lock(); defer { lock.unlock() }
        return isTransportAvailable
    }

    public func receive(_ envelope: SignalEnvelope) throws -> SignalIngressResult {
        // 1. An unreachable transport delivered nothing. Refused with the
        //    reason named: not evidence, and not a stop either, because a stop
        //    nobody sent is a stop nobody meant.
        guard transportAvailable else {
            return SignalIngressResult(
                disposition: .refused, handle: nil, receipt: nil, refusal: .transportOutage
            )
        }

        let bodyDigest = SignalGrammar.bodyDigest(envelope.body)
        let handle = SignalHandle(
            messageID: envelope.messageID,
            senderIdentifier: envelope.senderIdentifier,
            bodyDigest: bodyDigest
        )

        // 2. Durable dedupe, keyed on the message id, before anything is
        //    decided. At-most-once here is a primary key in the same store the
        //    ledger uses, not a set in memory: a restarted inbox must not
        //    reopen a message it already handled. Keyed on the id alone, so a
        //    sender cannot restate a delivered message as something else by
        //    reusing the id with a different body.
        guard try isFirstDelivery(envelope, bodyDigest: bodyDigest) else {
            return SignalIngressResult(
                disposition: .refused, handle: handle, receipt: nil, refusal: .duplicateMessage
            )
        }

        // 3. STOP, before every trust check. Sender pinning, safety number and
        //    attachments are evidence concerns. None of them may suppress a
        //    stop: a stop from a sender whose key just changed is precisely the
        //    case where stopping matters most, and refusing it there would be
        //    failing open at the worst moment.
        if SignalGrammar.containsStop(envelope.body) {
            return SignalIngressResult(
                disposition: .stop,
                handle: handle,
                receipt: SignalReceipt(
                    messageID: envelope.messageID,
                    senderIdentifier: envelope.senderIdentifier,
                    bodyDigest: bodyDigest,
                    disposition: .stop
                ),
                refusal: nil
            )
        }

        // 4. Everything below is the evidence path, and it fails closed.
        guard let pinned = pinnedSenders[envelope.senderIdentifier] else {
            return refuse(handle, .senderNotPinned)
        }
        guard pinned.safetyNumber == envelope.safetyNumber else {
            // A changed safety number means the key behind the identity
            // changed. The identity is no longer evidence of anything, and
            // continuing silently is the failure this refuses.
            return refuse(handle, .safetyNumberDrift)
        }
        guard envelope.attachmentCount == 0 else {
            // An attachment is content this boundary cannot inspect or bound.
            // Evidence has to be exactly the control grammar and nothing else,
            // so a message carrying one is refused rather than partly read.
            return refuse(handle, .attachmentPresent)
        }

        switch SignalGrammar.parseEvidenceReference(envelope.body) {
        case .failure(let refusal):
            return refuse(handle, refusal)
        case .success:
            return SignalIngressResult(
                disposition: .evidence,
                handle: handle,
                receipt: SignalReceipt(
                    messageID: envelope.messageID,
                    senderIdentifier: envelope.senderIdentifier,
                    bodyDigest: bodyDigest,
                    disposition: .evidence
                ),
                refusal: nil
            )
        }
    }

    private func refuse(_ handle: SignalHandle, _ refusal: SignalRefusal) -> SignalIngressResult {
        // A refusal never carries a receipt. A receipt attests that a message
        // was accepted as something; there is nothing to attest to here.
        SignalIngressResult(disposition: .refused, handle: handle, receipt: nil, refusal: refusal)
    }

    /// True only for the first delivery of this message id.
    private func isFirstDelivery(_ envelope: SignalEnvelope, bodyDigest: String) throws -> Bool {
        let identifier = try LedgerOperationID("signal.\(envelope.messageID)")
        let row = try LedgerRow(
            operationID: identifier,
            digest: LedgerDigest.over(Array(envelope.body.utf8)),
            state: .settledSucceeded,
            sequence: 1
        )
        return try dedupeStore.createIfAbsent(row).created
    }
}
