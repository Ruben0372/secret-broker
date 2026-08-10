import Foundation
import Testing

/// The vendored corpora are the oracle for every other suite here. If they
/// drift, are truncated, or are quietly edited, every downstream known-answer
/// test still passes while proving nothing. So the corpora are checked first,
/// by recomputation, on every run.
@Suite("Vendored vector integrity")
struct VendoredVectorIntegrityTests {
    /// Exactly the files the upstream publisher ships, so a vendored set that
    /// gained or lost a file fails rather than silently narrowing the corpus.
    static let expectedApprovalVectors = [
        "approval_request_v1",
        "cross_domain_rejection_v1",
        "enrollment_record_v1",
        "gateway_receipt_v1",
        "owner_control_continuity_v1",
        "owner_control_cross_domain_v1",
        "owner_control_decision_v1",
        "owner_control_manifest_v1",
        "sas_derivation_v1",
        "signing_context_separation_v1",
        "task_decision_v1",
        "task_manifest_v1",
        "timestamps_v1",
        "unknown_fields_v1",
    ]

    @Test("Every approval vector recomputes to its published digest")
    func approvalDigestsRecompute() throws {
        let published = try ContractVectorFixtures.approvalDigests
        #expect(
            published.count == Self.expectedApprovalVectors.count,
            "published digest listing has \(published.count) entries, expected \(Self.expectedApprovalVectors.count)"
        )

        var verified = 0
        for name in Self.expectedApprovalVectors {
            let expected = try #require(published[name], "no published digest for \(name)")
            let bytes = try ContractVectorFixtures.data(
                at: ContractVectorFixtures.approvalRoot.appendingPathComponent("\(name).json")
            )
            let actual = ContractVectorFixtures.sha256Hex(bytes)
            #expect(
                actual == expected,
                "\(name) digests to \(actual), published \(expected). The vendored bytes no longer match the reviewed corpus."
            )
            verified += 1
        }
        // Non-vacuity: the loop must actually have run over every vector.
        #expect(verified == 14, "verified \(verified) approval vectors, expected exactly 14")
    }

    @Test("The digest listing names every vendored vector and nothing else")
    func approvalListingIsComplete() throws {
        let published = Set(try ContractVectorFixtures.approvalDigests.keys)
        let onDisk = Set(
            try FileManager.default
                .contentsOfDirectory(atPath: ContractVectorFixtures.approvalRoot.path)
                .filter { $0.hasSuffix(".json") && $0 != "DIGESTS.json" }
                .map { String($0.dropLast(".json".count)) }
        )
        #expect(published == onDisk, "listing and directory disagree: \(published.symmetricDifference(onDisk))")
        #expect(
            !published.contains("DIGESTS"),
            "the listing must exclude itself, or it could never be satisfied"
        )
    }

    @Test("The authority corpus recomputes to the digest named in the claim")
    func authorityDigestRecomputes() throws {
        let bytes = try ContractVectorFixtures.data(
            at: ContractVectorFixtures.authorityRoot.appendingPathComponent("authority-v1-vectors.json")
        )
        let actual = ContractVectorFixtures.sha256Hex(bytes)
        #expect(
            actual == ContractVectorFixtures.authorityVectorsDigest,
            "authority corpus digests to \(actual), claim named \(ContractVectorFixtures.authorityVectorsDigest)"
        )
    }

    @Test("The integrity check is wired to real bytes and would notice a change")
    func integrityCheckIsWiredCorrectly() throws {
        // A digest checker that reads nothing passes everything. Prove it reads
        // real content, and prove a single flipped byte changes the answer.
        let path = ContractVectorFixtures.approvalRoot.appendingPathComponent("task_manifest_v1.json")
        var bytes = try ContractVectorFixtures.data(at: path)
        #expect(bytes.count > 200, "vector looks truncated at \(bytes.count) bytes")

        let original = ContractVectorFixtures.sha256Hex(bytes)
        bytes[bytes.count - 1] = bytes[bytes.count - 1] ^ 0x01
        let mutated = ContractVectorFixtures.sha256Hex(bytes)
        #expect(original != mutated, "the hasher returned the same digest for different bytes")

        // And the hasher agrees with a published known answer, so it is not
        // merely self-consistent.
        let empty = ContractVectorFixtures.sha256Hex(Data())
        #expect(
            empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of empty input is wrong, so every digest here is untrustworthy"
        )
    }

    @Test("Provenance is recorded beside every vendored set")
    func provenanceIsRecorded() throws {
        for root in [ContractVectorFixtures.approvalRoot, ContractVectorFixtures.authorityRoot] {
            let provenance = root.appendingPathComponent("PROVENANCE.md")
            let text = try String(contentsOf: provenance, encoding: .utf8)
            #expect(
                text.contains("EXTERNAL VENDORED FIXTURE, NOT AUTHORED HERE"),
                "\(root.lastPathComponent) provenance does not mark the set external"
            )
            #expect(text.contains("Source commit"), "\(root.lastPathComponent) provenance names no source commit")
        }

        let approval = try String(
            contentsOf: ContractVectorFixtures.approvalRoot.appendingPathComponent("PROVENANCE.md"),
            encoding: .utf8
        )
        #expect(approval.contains(ContractVectorFixtures.Provenance.approvalCommit))
        #expect(approval.contains("ARM-47"), "the known escaping gap must stay named, not silently carried")

        let authority = try String(
            contentsOf: ContractVectorFixtures.authorityRoot.appendingPathComponent("PROVENANCE.md"),
            encoding: .utf8
        )
        #expect(authority.contains(ContractVectorFixtures.Provenance.authorityCommit))
    }
}
