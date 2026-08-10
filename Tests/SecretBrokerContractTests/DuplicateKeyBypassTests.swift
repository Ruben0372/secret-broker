import Foundation
import SecretBrokerContracts
import Testing

/// The duplicate-key parser differential, at the approval-object layer.
///
/// Two JSON readers disagree about which value survives when a key appears
/// twice: one keeps the first, one keeps the last. So one set of bytes is a
/// task-approval object to one implementation and an owner-control object to
/// the other, which is task authority standing in for owner control at the byte
/// level, decided by nothing more than which parser you happen to be.
///
/// A validator whose only entry takes an already-parsed dictionary cannot see
/// this at all. By the time it runs, one of the two domains has already been
/// silently discarded and the ambiguity is gone. That is why the byte-level
/// gate is mandatory rather than an extra layer: canonical-on-input is the
/// front door, not a corridor further inside.
///
/// This is the ARM-32 F1 differential reappearing here. It is a SIBLING of the
/// ARM-48 Unicode-canonically-equivalent-key case, not the same thing: these
/// keys are byte-identical duplicates, which is settled, while ARM-48 concerns
/// keys that differ in bytes and are canonically equivalent, which upstream
/// deliberately leaves unpinned.
@Suite("Duplicate-key substitution bypass")
struct DuplicateKeyBypassTests {
    static func duplicateDomainCases() throws -> [[String: Any]] {
        let file = try ContractVectorFixtures.json(
            at: ContractVectorFixtures.approvalRoot
                .appendingPathComponent("cross_domain_rejection_v1.json")
        )
        let cases = try #require(file["cases"] as? [[String: Any]])
        return cases.filter { $0["raw_json"] != nil }
    }

    @Test("The corpus publishes both orderings, and both are driven")
    func bothOrderingsArePresent() throws {
        let cases = try Self.duplicateDomainCases()
        #expect(cases.count == 2, "expected both duplicate-domain orderings, found \(cases.count)")
        let names = Set(cases.compactMap { $0["case"] as? String })
        #expect(names.contains("duplicate_domain_owner_control_then_task_approval"))
        #expect(names.contains("duplicate_domain_task_approval_then_owner_control"))
    }

    /// The finding itself: parse-then-validate accepts one of the two
    /// orderings, because the parser has already thrown away the other domain.
    @Test("Parsing first loses the ambiguity, which is why it is not the entry point")
    func parseFirstLosesTheAmbiguity() throws {
        var acceptedAfterParsing: [String] = []
        for testCase in try Self.duplicateDomainCases() {
            let name = testCase["case"] as? String ?? "unnamed"
            let raw = try #require(testCase["raw_json"] as? String)
            let bytes = Array(raw.utf8)

            guard let parsed = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else {
                continue
            }
            if ApprovalObjectValidator.validate(parsed, as: .taskManifest) == nil {
                acceptedAfterParsing.append(name)
            }
        }
        // Documented, not asserted away: exactly one ordering survives a
        // parse-first path on this platform, and which one depends on the
        // reader. This test records the hazard rather than blessing it.
        #expect(
            acceptedAfterParsing.count == 1,
            "expected exactly one ordering to survive a parse-first path, saw \(acceptedAfterParsing)"
        )
    }

    /// The fix: the byte-level entry refuses both orderings before parsing.
    @Test("The byte-level entry refuses BOTH orderings")
    func byteLevelEntryRefusesBoth() throws {
        var driven = 0
        for testCase in try Self.duplicateDomainCases() {
            let name = testCase["case"] as? String ?? "unnamed"
            let raw = try #require(testCase["raw_json"] as? String)
            let rejection = ApprovalObjectValidator.validate(bytes: Array(raw.utf8), as: .taskManifest)
            #expect(
                rejection == .nonCanonicalEncoding,
                "\(name): refused with \(rejection?.rawValue ?? "ACCEPTED"), expected nonCanonicalEncoding"
            )
            driven += 1
        }
        #expect(driven == 2, "drove \(driven) duplicate-domain orderings, expected exactly 2")
    }

    /// The gate must be load-bearing rather than decorative: a genuine object
    /// still passes through the same entry.
    @Test("The byte-level entry still accepts the genuine article")
    func byteLevelEntryAcceptsGenuine() throws {
        let file = try ContractVectorFixtures.json(
            at: ContractVectorFixtures.approvalRoot.appendingPathComponent("task_manifest_v1.json")
        )
        let canonical = try #require(file["canonical_json"] as? String)
        #expect(
            ApprovalObjectValidator.validate(bytes: Array(canonical.utf8), as: .taskManifest) == nil,
            "the byte-level entry refused a genuine canonical task manifest"
        )

        // And it refuses the same genuine bytes presented as the wrong type, so
        // adding the byte gate did not weaken the separation it sits in front of.
        #expect(
            ApprovalObjectValidator.validate(bytes: Array(canonical.utf8), as: .ownerControlManifest) != nil,
            "a genuine task manifest was accepted as an owner-control manifest through the byte entry"
        )
    }

    /// Non-canonical spellings that are not duplicate keys are refused too, so
    /// the gate is the general rule rather than a special case bolted on for
    /// one vector.
    @Test("The byte-level entry refuses other non-canonical spellings")
    func byteLevelEntryRefusesOtherNonCanonicalForms() throws {
        let file = try ContractVectorFixtures.json(
            at: ContractVectorFixtures.approvalRoot.appendingPathComponent("task_manifest_v1.json")
        )
        let canonical = try #require(file["canonical_json"] as? String)

        // Same object, one space added. Parses identically, different bytes.
        let spaced = canonical.replacingOccurrences(of: "{\"action\"", with: "{ \"action\"")
        #expect(spaced != canonical, "the mutation did not apply")
        #expect(
            ApprovalObjectValidator.validate(bytes: Array(spaced.utf8), as: .taskManifest) == .nonCanonicalEncoding,
            "insignificant whitespace was accepted by the byte-level entry"
        )
    }
}
