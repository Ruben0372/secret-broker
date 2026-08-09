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
        #expect(dependencies == ["SecretBrokerContracts"])

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

    @Test("Adapters ship fakes only, all sources under Fakes")
    func adaptersAreFakeOnly() {
        #expect(
            FileManager.default.fileExists(atPath: Self.fakesDirectory.path),
            "Sources/SecretBrokerAdapters/Fakes missing"
        )
        let sources = BootstrapTestSupport.swiftFiles(under: Self.adaptersDirectory)
        #expect(!sources.isEmpty, "adapters target has no sources")
        for file in sources {
            #expect(
                file.path.hasPrefix(Self.fakesDirectory.path),
                "\(file.lastPathComponent) sits outside Fakes; a real adapter needs security review"
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
