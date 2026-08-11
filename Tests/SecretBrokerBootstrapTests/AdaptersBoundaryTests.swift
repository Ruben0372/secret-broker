import Foundation
import Testing

/// The adapters target exists to house test doubles for the custody seam. It
/// must stay fake-only and must never become reachable from the daemon: the
/// daemon links contracts alone, so no adapter, real or fake, can be pulled
/// into the runtime by a later change without failing these tests.
@Suite("Adapters boundary")
struct AdaptersBoundaryTests {
    static let adaptersDirectory = BootstrapTestSupport.packageRoot
        .appendingPathComponent("Sources")
        .appendingPathComponent("SecretBrokerAdapters")

    static let fakesDirectory = adaptersDirectory.appendingPathComponent("Fakes")

    @Test("Manifest declares the adapters target")
    func manifestDeclaresAdaptersTarget() {
        #expect(
            BootstrapTestSupport.target(named: "SecretBrokerAdapters") != nil,
            "SecretBrokerAdapters target missing from Package.swift"
        )
    }

    @Test("Adapters depend only on the contracts module")
    func adaptersDependencyAllowlist() throws {
        let adapters = try #require(
            BootstrapTestSupport.target(named: "SecretBrokerAdapters"),
            "SecretBrokerAdapters target missing from Package.swift"
        )
        #expect(BootstrapTestSupport.dependencyNames(of: adapters) == ["SecretBrokerContracts"])
    }

    @Test("Adapters are not linkable into the daemon target")
    func adaptersUnreachableFromDaemon() throws {
        let daemon = try #require(
            BootstrapTestSupport.target(named: "SecretBrokerDaemon"),
            "SecretBrokerDaemon target missing from Package.swift"
        )
        let dependencies = BootstrapTestSupport.dependencyNames(of: daemon)
        #expect(!dependencies.contains("SecretBrokerAdapters"))
        #expect(dependencies == ["SecretBrokerContracts", "SecretBrokerCore"])

        for file in BootstrapTestSupport.swiftFiles(
            under: BootstrapTestSupport.packageRoot
                .appendingPathComponent("Sources")
                .appendingPathComponent("SecretBrokerDaemon")
        ) {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(
                !text.contains("import SecretBrokerAdapters"),
                "\(file.lastPathComponent) imports the adapters module"
            )
        }
    }

    @Test("Test target reaches the custody seam through the adapters fake")
    func testTargetDependsOnAdapters() throws {
        let tests = try #require(BootstrapTestSupport.target(named: "SecretBrokerBootstrapTests"))
        #expect(BootstrapTestSupport.dependencyNames(of: tests).contains("SecretBrokerAdapters"))
    }

    /// Non-fake adapter sources that have been through security review, named
    /// one by one. ARM-26 reviewed the Keychain custody store, which is the
    /// "a real adapter needs security review" case the original fakes-only pin
    /// anticipated rather than forbade forever.
    ///
    /// This is a narrowing, not a relaxation. A NEW non-fake adapter that
    /// nobody has reviewed still fails, because it will not be on this list,
    /// and the fakes still have to stay under Fakes/. What actually keeps
    /// custody isolated is unchanged and asserted elsewhere: adapters is not a
    /// daemon dependency, is not an exported product, and the daemon artifact
    /// carries no Keychain symbols.
    /// ARM-27 adds the SQLite reservation ledger. Same reasoning as the entry
    /// above and the same limits: it is named individually, an unreviewed
    /// sibling still fails, and none of the controls that actually keep the
    /// runtime isolated are touched by its presence. It reaches one file at a
    /// caller-supplied path, no credential and no Keychain, which is why it can
    /// sit in adapters at all.
    /// ARM-29 adds the fake Signal ingress. Three files, named individually
    /// rather than admitting a whole directory, because a directory-shaped
    /// exemption is how the next unreviewed adapter arrives. They reach no
    /// network and no account: real device linkage is disabled and asserted.
    static let reviewedNonFakeSources: Set<String> = [
        "KeychainStore.swift", "SQLiteLedger.swift",
        "SignalMessage.swift", "SignalReceipt.swift", "SignalInbox.swift",
    ]

    @Test("Adapters ship fakes only, apart from explicitly reviewed sources")
    func adaptersAreFakeOnly() {
        #expect(
            FileManager.default.fileExists(atPath: Self.fakesDirectory.path),
            "Sources/SecretBrokerAdapters/Fakes missing"
        )
        let sources = BootstrapTestSupport.swiftFiles(under: Self.adaptersDirectory)
        #expect(!sources.isEmpty, "adapters target has no sources")
        for file in sources {
            let underFakes = file.path.hasPrefix(Self.fakesDirectory.path)
            let reviewed = Self.reviewedNonFakeSources.contains(file.lastPathComponent)
            #expect(
                underFakes || reviewed,
                "\(file.lastPathComponent) sits outside Fakes and is not a reviewed adapter; a real adapter needs security review"
            )
            #expect(
                !(underFakes && reviewed),
                "\(file.lastPathComponent) is listed as a reviewed non-fake source but lives under Fakes"
            )
        }
    }

    @Test("Custody fakes live in adapters, not in the test target")
    func custodyFakesRelocatedOutOfTests() throws {
        // Assembled at runtime so this file does not match its own scan.
        let conformanceNeedle = ": " + "SecretCustodian"
        let testsRoot = BootstrapTestSupport.packageRoot.appendingPathComponent("Tests")
        for file in BootstrapTestSupport.swiftFiles(under: testsRoot) {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(
                !text.contains(conformanceNeedle),
                "\(file.lastPathComponent) declares a custodian; fakes belong in the adapters target"
            )
        }
    }

    @Test("Forbidden runtime token scan demonstrably covers the adapters target")
    func tokenScanCoversAdapters() throws {
        let scanned = BootstrapTestSupport.swiftFiles(
            under: BootstrapTestSupport.packageRoot.appendingPathComponent("Sources")
        )
        #expect(
            scanned.contains { $0.path.hasPrefix(Self.adaptersDirectory.path) },
            "adapters sources are not part of the scanned source tree"
        )
        for file in scanned where file.path.hasPrefix(Self.adaptersDirectory.path) {
            let text = try String(contentsOf: file, encoding: .utf8)
            for token in RuntimeIsolationTests.forbiddenRuntimeTokens {
                #expect(
                    !text.contains(token),
                    "\(file.lastPathComponent) contains forbidden runtime token: \(token)"
                )
            }
        }
    }
}
