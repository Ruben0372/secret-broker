import Foundation
import Testing

/// Provenance facts this repository must never lose. The legacy bash proof of
/// concept and the reviewed operating guide merge are history evidence; the
/// scripts stay tracked but are never part of the Armel runtime.
@Suite("Legacy provenance")
struct ProvenanceTests {
    /// Last commit of the legacy bash proof of concept.
    static let legacyBaselineSHA = "fec8ddae1586c58efd04cabf0593627e3f4f39e8"

    /// Merge commit of the independently reviewed operating guide (PR 2).
    /// Verified during ARM-5 setup on 2026-08-09 to equal current main.
    static let operatingGuideMergeSHA = "55f101e5138d7c98beddd025647f9ef0ee6c2b4b"

    @Test("Legacy bash baseline remains reachable in history")
    func legacyBaselineRevisionPreserved() throws {
        let type = try BootstrapTestSupport.run(["git", "cat-file", "-t", Self.legacyBaselineSHA])
        #expect(type.status == 0, "legacy baseline commit missing: \(type.stderr)")
        #expect(type.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "commit")

        let ancestry = try BootstrapTestSupport.run([
            "git", "merge-base", "--is-ancestor", Self.legacyBaselineSHA, "HEAD",
        ])
        #expect(ancestry.status == 0, "legacy baseline is no longer an ancestor of HEAD")
    }

    @Test("Operating guide merge is recorded and part of current history")
    func operatingGuideMergeRecorded() throws {
        let subject = try BootstrapTestSupport.run([
            "git", "log", "-1", "--format=%s", Self.operatingGuideMergeSHA,
        ])
        #expect(subject.status == 0, "operating guide merge commit missing: \(subject.stderr)")
        #expect(subject.stdout.contains("Merge pull request #2"))

        let ancestry = try BootstrapTestSupport.run([
            "git", "merge-base", "--is-ancestor", Self.operatingGuideMergeSHA, "HEAD",
        ])
        #expect(ancestry.status == 0, "operating guide merge is no longer an ancestor of HEAD")
    }

    @Test("Apache license and legacy scripts stay tracked as provenance")
    func licenseAndLegacyScriptsTracked() throws {
        let files = try BootstrapTestSupport.run(["git", "ls-files"])
        #expect(files.status == 0)
        let tracked = Set(files.stdout.split(separator: "\n").map(String.init))
        #expect(tracked.contains("LICENSE"))
        #expect(tracked.contains("load-secrets.sh"))
        #expect(tracked.contains("add-secret.sh"))

        let license = try String(
            contentsOf: BootstrapTestSupport.packageRoot.appendingPathComponent("LICENSE"),
            encoding: .utf8
        )
        #expect(license.contains("Apache License"))
    }
}
