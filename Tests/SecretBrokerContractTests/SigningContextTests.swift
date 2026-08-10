import Foundation
import SecretBrokerContracts
import Testing

/// Known-answer reproduction of the signing-context construction, DISC-042.
///
/// This repository is the first consumer of that construction, and it is a
/// local definition pending confirm-or-freeze at ARM-14. It is enforced here as
/// a constant that recomputes every run, so if the tags, the separator, or the
/// covered range move upstream, this fails rather than drifting quietly.
@Suite("Signing context separation, DISC-042")
struct SigningContextTests {
    static var corpus: [String: Any] {
        get throws {
            try ContractVectorFixtures.json(
                at: ContractVectorFixtures.approvalRoot
                    .appendingPathComponent("signing_context_separation_v1.json")
            )
        }
    }

    @Test("Both tags match the published constants")
    func tagsMatchPublished() throws {
        let published = try #require(try Self.corpus["tags"] as? [String: String])
        #expect(SigningContext.taskApproval.tag == published["task_approval"])
        #expect(SigningContext.ownerControl.tag == published["owner_control"])
        #expect(SigningContext.separator == 0x00)
        #expect(
            SigningContext.disc042Status.contains("ARM-14-pending"),
            "the provisional status must stay marked until ARM-14 decides"
        )
    }

    @Test("Every published pairing reproduces its preimage digest")
    func preimageDigestsReproduce() throws {
        let cases = try #require(try Self.corpus["cases"] as? [[String: Any]])
        #expect(cases.count == 4, "expected exactly 4 published pairings, found \(cases.count)")

        var reproduced = 0
        var correctPairings = 0
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            let canonical = try #require(testCase["canonical_json"] as? String)
            let tag = try #require(testCase["tag"] as? String)
            let expected = try #require(testCase["signing_preimage_sha256_hex"] as? String)
            let isCorrect = try #require(testCase["is_the_correct_pairing"] as? Bool)

            let context = try #require(
                SigningContext.allCases.first { $0.tag == tag },
                "\(name): unknown tag \(tag)"
            )
            let digest = try context.preimageDigestHex(canonicalJSON: canonical)
            #expect(digest == expected, "\(name): preimage digest diverges from the published value")
            reproduced += 1
            if isCorrect { correctPairings += 1 }
        }
        #expect(reproduced == 4, "reproduced \(reproduced) of 4")
        // Non-vacuity of the corpus itself: it must contain both correct and
        // incorrect pairings, or it could not demonstrate separation at all.
        #expect(correctPairings == 2, "expected 2 correct and 2 incorrect pairings, saw \(correctPairings) correct")
    }

    @Test("The same bytes under the two tags never agree")
    func sameBytesDifferentTagsDiverge() throws {
        let cases = try #require(try Self.corpus["cases"] as? [[String: Any]])
        // Group the published canonical bytes and check each appears under both
        // tags with different digests. This is the separation claim itself.
        var byCanonical: [String: [String]] = [:]
        for testCase in cases {
            guard let canonical = testCase["canonical_json"] as? String,
                  let digest = testCase["signing_preimage_sha256_hex"] as? String
            else { continue }
            byCanonical[canonical, default: []].append(digest)
        }
        #expect(byCanonical.count == 2, "expected two distinct canonical payloads")

        var compared = 0
        for (canonical, digests) in byCanonical {
            #expect(digests.count == 2, "payload appears \(digests.count) times, expected under both tags")
            #expect(Set(digests).count == 2, "the same bytes produced the same digest under both tags")

            // And recompute both sides rather than trusting the published pair.
            let task = try SigningContext.taskApproval.preimageDigestHex(canonicalJSON: canonical)
            let owner = try SigningContext.ownerControl.preimageDigestHex(canonicalJSON: canonical)
            #expect(task != owner, "a signature over these bytes would transfer between domains")
            #expect(Set([task, owner]) == Set(digests), "recomputed digests do not match the published pair")
            compared += 1
        }
        #expect(compared == 2)
    }

    @Test("The tag is derived from the object type and cannot be supplied")
    func tagIsDerivedNotRead() {
        // The separation rests on this: a caller cannot choose the tag, so a
        // forgetful validator still fails closed. Expressed as a total function
        // from type to context, with no path that reads a tag from input.
        for type in ApprovalObjectType.allCases {
            let context = SigningContext.forObjectType(type)
            switch type.family {
            case .taskApproval: #expect(context == .taskApproval)
            case .ownerControl: #expect(context == .ownerControl)
            }
        }
        #expect(ApprovalObjectType.allCases.count == 7)
    }

    @Test("The preimage guard fails closed if the separator invariant is broken")
    func separatorGuardFailsClosed() {
        // A canonical encoding can never contain a raw NUL. If one ever did,
        // the construction would stop being injective, so the guard refuses
        // rather than producing a digest that looks fine and is not.
        #expect(throws: SigningContext.PreimageError.self) {
            try SigningContext.taskApproval.preimage(canonicalBytes: [0x7b, 0x00, 0x7d])
        }
        // And the ordinary path still works, so the guard is not refusing
        // everything.
        #expect(throws: Never.self) {
            try SigningContext.taskApproval.preimage(canonicalBytes: [0x7b, 0x7d])
        }
    }
}
