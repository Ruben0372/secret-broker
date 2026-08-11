import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import Testing

/// Signal ingress, and the boundary that is the entire point of it.
///
/// ACCEPTANCE: Signal can supply EVIDENCE or a fail-safe STOP, and never task
/// authority or approval by itself. A Signal message must not be promotable
/// into an authorizing act.
///
/// Structural where possible, checked where not, and the difference is stated
/// rather than blurred:
///
/// STRUCTURAL. `SignalDisposition` has no authority case, so "Signal
/// authorized this" cannot be written down. The disposition set is pinned as an
/// exact reviewed set, not scanned for suspicious names, because a scan for
/// names like `approve` catches `.approved` and misses `.greenlit`. That lesson
/// cost a correction in ARM-28 and is not being relearned here.
///
/// CRYPTOGRAPHIC. A Signal receipt is domain separated into a namespace that
/// the approval construction does not share, so a Signal receipt presented as
/// an approval receipt does not verify. That is proven by substitution rather
/// than asserted.
///
/// THE ASYMMETRY THAT MATTERS. Evidence fails CLOSED and STOP fails SAFE, so
/// they are deliberately not equally strict. A malformed evidence message is
/// refused; a malformed message that still contains a recognisable STOP still
/// stops. Making them equally strict in either direction breaks one of them: a
/// strict STOP fails open exactly when it is needed, and a permissive evidence
/// path is how a near-miss gets promoted into a fact.
///
/// Everything runs against a fake transport with real linkage disabled and
/// asserted. No network, no account, no credentials.

@Suite("Signal ingress, evidence and stop but never authority")
struct SignalTests {
    static let pinnedSender = SignalSender(
        serviceIdentifier: "arm29.fake.sender.pinned",
        safetyNumber: "11111 22222 33333 44444 55555 66666"
    )

    static func disposableDirectory(_ label: String = #function) throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("arm29-disposable")
            .appendingPathComponent("\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    static func makeInbox(in directory: URL) throws -> SignalInbox {
        SignalInbox(
            pinnedSenders: [pinnedSender],
            dedupeStore: try SQLiteLedgerStore(
                path: directory.appendingPathComponent("signal.sqlite").path
            )
        )
    }

    static func envelope(
        id: String = "msg-1",
        sender: String = pinnedSender.serviceIdentifier,
        safetyNumber: String = pinnedSender.safetyNumber,
        body: String = "ARMEL STOP",
        attachments: Int = 0
    ) -> SignalEnvelope {
        SignalEnvelope(
            messageID: id,
            senderIdentifier: sender,
            safetyNumber: safetyNumber,
            body: body,
            attachmentCount: attachments
        )
    }

    // MARK: The acceptance, structurally

    @Test("No disposition conveys authority, and the set is exactly the reviewed one")
    func noDispositionConveysAuthority() {
        // Exact set, not a name scan. A scan for approval-shaped names catches
        // `.approved` and misses `.greenlit`, `.sanctioned` or `.blessed`.
        #expect(
            Set(SignalDisposition.allCases.map(\.rawValue)) == ["evidence", "stop", "refused"],
            "the disposition set changed: \(SignalDisposition.allCases.map(\.rawValue).sorted()). A new disposition is a new thing Signal can mean, and is a reviewed change."
        )
        for disposition in SignalDisposition.allCases {
            #expect(
                !disposition.conveysAuthority,
                "\(disposition.rawValue) conveys authority; Signal supplies evidence or a stop, never an authorizing act"
            )
        }
        // POSITIVE CONTROL: conveysAuthority is a real classification and not a
        // property hardcoded false. If nothing could ever be true, the loop
        // above proves nothing about the classification.
        #expect(
            SignalDisposition.allCases.contains(where: { $0.isActionable }),
            "no disposition is actionable, so the ingress can never do anything and the check above is vacuous"
        )
    }

    @Test("A Signal receipt is refused by every approval validator")
    func signalReceiptIsNotAnApprovalObject() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)
        let result = try inbox.receive(Self.envelope(body: "ARMEL EVIDENCE ref-7f3a"))
        let receipt = try #require(result.receipt)

        // Presented as each approval object type in turn. None may accept it.
        // This is the ARM-25 substitution discipline: separation is proven by
        // driving the thing through the validator it must not satisfy, not by
        // observing that a field is absent.
        let encoded = try JSONEncoder().encode(receipt)
        var refused = 0
        for type in ApprovalObjectType.allCases {
            let rejection = ApprovalObjectValidator.validate(bytes: Array(encoded), as: type)
            #expect(
                rejection != nil,
                "a Signal receipt was ACCEPTED as \(type.schema); Signal can be promoted into an approval"
            )
            refused += 1
        }
        #expect(refused == ApprovalObjectType.allCases.count)
        #expect(refused == 7, "expected 7 approval types, drove \(refused)")
    }

    @Test("A Signal receipt does not verify under any approval signing context")
    func signalReceiptDoesNotVerifyAsApproval() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)
        let result = try inbox.receive(Self.envelope(body: "ARMEL EVIDENCE ref-7f3a"))
        let receipt = try #require(result.receipt)

        // The same canonical bytes, digested under the approval tags, produce
        // different values. The Signal namespace is not a case of the approval
        // construction, so the two can never collide.
        let canonical = receipt.canonicalBytes
        for context in SigningContext.allCases {
            let approvalDigest = try context.preimageDigestHex(
                canonicalJSON: String(decoding: canonical, as: UTF8.self)
            )
            #expect(
                approvalDigest != receipt.digest,
                "a Signal receipt digest collides with the \(context.tag) construction"
            )
        }
        #expect(
            SignalReceipt.evidenceDomainTag.hasPrefix("armel.broker.signal."),
            "the Signal domain is not in its own namespace"
        )
        for context in SigningContext.allCases {
            #expect(
                !context.tag.hasPrefix("armel.broker.signal."),
                "an approval tag shares the Signal namespace: \(context.tag)"
            )
        }
    }

    // MARK: Pinned sender

    @Test("A message from an unpinned sender is not evidence")
    func unpinnedSenderIsNotEvidence() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        let result = try inbox.receive(
            Self.envelope(id: "msg-stranger", sender: "arm29.fake.sender.stranger", body: "ARMEL EVIDENCE ref-1")
        )
        #expect(result.disposition == .refused)
        #expect(result.refusal == .senderNotPinned)
        #expect(result.receipt == nil, "an unpinned sender was issued a receipt")

        // POSITIVE CONTROL: the pinned sender's identical message IS evidence,
        // so the refusal is about the sender rather than about an inbox that
        // refuses everything.
        let pinned = try inbox.receive(Self.envelope(id: "msg-pinned", body: "ARMEL EVIDENCE ref-1"))
        #expect(pinned.disposition == .evidence)
        #expect(pinned.receipt != nil)
    }

    @Test("Safety-number drift invalidates trust and does not silently continue")
    func safetyNumberDriftIsRefused() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        let drifted = try inbox.receive(
            Self.envelope(id: "msg-drift", safetyNumber: "99999 88888 77777 66666 55555 44444", body: "ARMEL EVIDENCE ref-2")
        )
        expectRefused(drifted, because: .safetyNumberDrift)

        // The distinction that matters: drift is refused for EVIDENCE, and a
        // STOP from the same drifted sender still stops. A changed safety
        // number means the peer may not be who it was, which is a reason to
        // stop trusting them for evidence and precisely NOT a reason to ignore
        // a stop.
        let stop = try inbox.receive(
            Self.envelope(id: "msg-drift-stop", safetyNumber: "99999 88888 77777 66666 55555 44444", body: "ARMEL STOP")
        )
        #expect(
            stop.disposition == .stop,
            "a STOP was dropped because the safety number drifted; the fail-safe path must not depend on trust"
        )
    }

    // MARK: Exact grammar

    @Test("Only the exact control grammar parses as evidence")
    func onlyExactGrammarParses() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        let nearMisses = [
            "armel evidence ref-1",
            "ARMEL  EVIDENCE ref-1",
            "ARMEL EVIDENCE",
            "ARMEL EVIDENCE ref-1 extra",
            "PREFIX ARMEL EVIDENCE ref-1",
            "ARMEL EVIDENCE ref-1 ",
            "ARMEL\tEVIDENCE ref-1",
            "ARMEL EVIDENCE ref\u{2010}1",
            "ARMEL EVIDENCE réf-1",
            "ARMELEVIDENCE ref-1",
        ]
        for (index, body) in nearMisses.enumerated() {
            let result = try inbox.receive(Self.envelope(id: "near-\(index)", body: body))
            #expect(
                result.disposition == .refused,
                "a near miss parsed as evidence: \(body.debugDescription) produced \(result.disposition.rawValue)"
            )
            #expect(result.receipt == nil)
        }

        // POSITIVE CONTROL: the exact form is accepted, so the refusals above
        // are about the grammar and not about a parser that rejects everything.
        let exact = try inbox.receive(Self.envelope(id: "exact", body: "ARMEL EVIDENCE ref-1"))
        #expect(exact.disposition == .evidence, "the exact grammar was refused, so nothing above was tested")
    }

    @Test("Canonicalization refuses variants rather than folding them together")
    func canonicalizationDoesNotSmuggleMeaning() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        // Each of these folds onto a valid token under some plausible
        // normalization: case folding, whitespace collapsing, Unicode
        // compatibility folding, or zero-width stripping. Folding is the hazard:
        // it lets a body that is NOT the control grammar arrive as though it
        // were, and the difference between the two is invisible afterwards.
        let smugglers = [
            "ARMEL EVIDENCE\u{200B} ref-1",
            "ARMEL EVIDENCE\u{00A0}ref-1",
            "ＡＲＭＥＬ ＥＶＩＤＥＮＣＥ ref-1",
            "ARMEL EVIDENCE ref-1\u{202E}",
            "ARMEL\u{0000}EVIDENCE ref-1",
        ]
        for (index, body) in smugglers.enumerated() {
            let result = try inbox.receive(Self.envelope(id: "smuggle-\(index)", body: body))
            #expect(
                result.disposition == .refused,
                "a folded variant was accepted: \(body.debugDescription)"
            )
        }
    }

    // MARK: Attachments

    @Test("An attachment never becomes evidence content")
    func attachmentsAreRefused() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        let withAttachment = try inbox.receive(
            Self.envelope(id: "msg-attach", body: "ARMEL EVIDENCE ref-3", attachments: 1)
        )
        expectRefused(withAttachment, because: .attachmentPresent)

        // A STOP carrying an attachment still stops. Same asymmetry as drift:
        // the attachment is a reason to distrust the content, never a reason to
        // ignore a stop.
        let stopWithAttachment = try inbox.receive(
            Self.envelope(id: "msg-attach-stop", body: "ARMEL STOP", attachments: 3)
        )
        #expect(stopWithAttachment.disposition == .stop)

        // POSITIVE CONTROL: the same evidence body with no attachment is
        // accepted.
        let clean = try inbox.receive(Self.envelope(id: "msg-clean", body: "ARMEL EVIDENCE ref-3"))
        #expect(clean.disposition == .evidence)
    }

    // MARK: Durable dedupe

    @Test("A duplicate message is refused, and the dedupe survives a restart")
    func duplicateMessageIsRefusedAcrossRestart() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("signal.sqlite").path

        let first: SignalIngressResult
        do {
            let inbox = SignalInbox(
                pinnedSenders: [Self.pinnedSender],
                dedupeStore: try SQLiteLedgerStore(path: path)
            )
            first = try inbox.receive(Self.envelope(id: "msg-dup", body: "ARMEL EVIDENCE ref-4"))
        }
        #expect(first.disposition == .evidence)

        // A NEW inbox over the same file. The dedupe is a durable primary key,
        // not a set held in memory, so a restart does not reopen the message.
        let restarted = SignalInbox(
            pinnedSenders: [Self.pinnedSender],
            dedupeStore: try SQLiteLedgerStore(path: path)
        )
        let replay = try restarted.receive(Self.envelope(id: "msg-dup", body: "ARMEL EVIDENCE ref-4"))
        expectRefused(replay, because: .duplicateMessage)
        #expect(replay.receipt == nil, "a duplicate was issued a second receipt")

        // POSITIVE CONTROL: a DIFFERENT message id from the same sender still
        // gets through after the restart, so dedupe is keyed on the message and
        // has not become a blanket refusal.
        let fresh = try restarted.receive(Self.envelope(id: "msg-fresh", body: "ARMEL EVIDENCE ref-5"))
        #expect(fresh.disposition == .evidence)
    }

    @Test("A duplicate message id carrying different bytes is refused, not re-evaluated")
    func duplicateIDWithDifferentBodyIsRefused() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        _ = try inbox.receive(Self.envelope(id: "msg-same", body: "ARMEL EVIDENCE ref-6"))
        // Same id, different body. Accepting this would let a sender restate a
        // delivered message as something else, which is the ARM-33 altered
        // replay in a different transport.
        let altered = try inbox.receive(Self.envelope(id: "msg-same", body: "ARMEL EVIDENCE ref-99"))
        expectRefused(altered, because: .duplicateMessage)
    }

    // MARK: STOP, the fail-safe path

    @Test("STOP works under partial and damaged input")
    func stopWorksUnderPartialInput() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        // Every one of these would be refused as evidence. All must still stop.
        // A stop that only works on a well-formed message fails exactly when
        // the sender is in trouble and typing badly.
        let damaged = [
            "ARMEL STOP",
            "armel stop",
            "  ARMEL   STOP  ",
            "ARMEL STOP now please",
            "help ARMEL STOP",
            "ARMEL STOP\u{200B}",
        ]
        for (index, body) in damaged.enumerated() {
            let result = try inbox.receive(Self.envelope(id: "stop-\(index)", body: body))
            #expect(
                result.disposition == .stop,
                "a damaged STOP did not stop: \(body.debugDescription) produced \(result.disposition.rawValue)"
            )
        }

        // POSITIVE CONTROL, and the boundary of the permissiveness: a body that
        // does not contain the stop token is NOT a stop. Otherwise the fail-safe
        // path would trigger on anything and become useless.
        let notAStop = try inbox.receive(Self.envelope(id: "not-stop", body: "ARMEL EVIDENCE ref-8"))
        #expect(notAStop.disposition == .evidence)
        let nonsense = try inbox.receive(Self.envelope(id: "nonsense", body: "good morning"))
        #expect(nonsense.disposition == .refused)
    }

    /// The other edge of the permissive path. A fail-safe that triggers on
    /// anything containing the letters is not fail-safe, it is broken: it would
    /// halt on a status update mentioning that something stopped, and the fix
    /// people reach for is to stop using the stop word.
    @Test("A word merely containing the stop token does not stop")
    func stopMatchesTokensNotSubstrings() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)

        let notStops = [
            "ARMEL EVIDENCE stopped",
            "ARMEL EVIDENCE unstoppable",
            "ARMEL EVIDENCE stopgap",
            "ARMEL EVIDENCE nonstop",
        ]
        for (index, body) in notStops.enumerated() {
            let result = try inbox.receive(Self.envelope(id: "substr-\(index)", body: body))
            #expect(
                result.disposition != .stop,
                "\(body.debugDescription) triggered a stop; the match is on substrings, not tokens"
            )
        }

        // POSITIVE CONTROL: the token on its own, in the same lowercase form,
        // does stop. So the refusals above are about word boundaries and not
        // about a matcher that stopped working.
        let real = try inbox.receive(Self.envelope(id: "substr-real", body: "armel stop"))
        #expect(real.disposition == .stop)
    }

    @Test("A STOP is not evidence, and carries no authority")
    func stopIsNotEvidence() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)
        let result = try inbox.receive(Self.envelope(id: "stop-alone", body: "ARMEL STOP"))

        #expect(result.disposition == .stop)
        #expect(!result.disposition.conveysAuthority)
        let receipt = try #require(result.receipt)
        #expect(
            receipt.domainTag == SignalReceipt.stopDomainTag,
            "a stop receipt carries the evidence domain, so the two can be confused"
        )
        #expect(SignalReceipt.stopDomainTag != SignalReceipt.evidenceDomainTag)
    }

    // MARK: Outage

    @Test("An outage fails safe and never fails open")
    func outageFailsSafe() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)
        inbox.setTransportAvailable(false)

        let result = try inbox.receive(Self.envelope(id: "msg-outage", body: "ARMEL EVIDENCE ref-9"))
        expectRefused(result, because: .transportOutage)
        #expect(
            result.receipt == nil,
            "an outage produced a receipt; an unreachable transport cannot attest to anything"
        )

        // The fail-safe direction: absence of Signal must never read as
        // permission. An outage does not become evidence, and it does not
        // become a stop either, because a stop nobody sent is a stop nobody
        // meant. It is simply refused, and the caller is told which.
        #expect(result.disposition != .evidence)
        #expect(result.disposition != .stop)

        // POSITIVE CONTROL: restoring the transport restores ingress.
        inbox.setTransportAvailable(true)
        let restored = try inbox.receive(Self.envelope(id: "msg-restored", body: "ARMEL EVIDENCE ref-9"))
        #expect(restored.disposition == .evidence)
    }

    // MARK: Opaque handles and real linkage

    @Test("The payload crosses as an opaque handle that cannot carry the body")
    func payloadCrossesAsAnOpaqueHandle() throws {
        let directory = try Self.disposableDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let inbox = try Self.makeInbox(in: directory)
        let body = "ARMEL EVIDENCE ref-a1b2c3d4"
        let result = try inbox.receive(Self.envelope(id: "msg-handle", body: body))
        let handle = try #require(result.handle)

        // The handle names the message and digests the body. It has no field
        // that could hold the body, which is the ARM-26 discipline: the only
        // thing that crosses is a reference.
        let surfaces = [
            ("handle", String(describing: handle)),
            ("receipt", String(describing: try #require(result.receipt))),
            ("result", String(describing: result)),
        ]
        for (label, surface) in surfaces {
            #expect(
                !surface.contains("ref-a1b2c3d4"),
                "\(label) carries the message body: \(surface)"
            )
        }
        // POSITIVE CONTROL: the handle really does identify the message, so the
        // absence above is redaction and not an empty handle.
        #expect(handle.messageID == "msg-handle")
        #expect(!handle.bodyDigest.isEmpty)
    }

    @Test("Real Signal linkage is disabled and every real path refuses")
    func realLinkageIsDisabled() {
        #expect(SignalInbox.isRealLinkageEnabled == false)
        #expect(!SignalInbox.realLinkageGate.isEmpty)
        #expect(throws: SignalRefusal.self, "a real linked device was constructed") {
            _ = try SignalInbox.linkedDeviceInbox(accountIdentifier: "would-be-real")
        }
    }
}

/// Reads better than repeating the pair at every call site, and keeps the
/// failure message naming both halves.
private func expectRefused(
    _ result: SignalIngressResult,
    because refusal: SignalRefusal,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    #expect(
        result.disposition == .refused,
        "expected refused, got \(result.disposition.rawValue)",
        sourceLocation: sourceLocation
    )
    #expect(
        result.refusal == refusal,
        "expected refusal \(refusal.rawValue), got \(result.refusal?.rawValue ?? "none")",
        sourceLocation: sourceLocation
    )
}
