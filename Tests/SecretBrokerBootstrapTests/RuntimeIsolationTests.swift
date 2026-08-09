import Foundation
import Testing

/// The legacy shell scripts are provenance only and must never become an Armel
/// runtime. These tests fail if the scripts, or any environment export or
/// process execution capability, become linkable into the daemon target.
@Suite("Runtime isolation from the legacy export path")
struct RuntimeIsolationTests {
    static let legacyScripts = ["load-secrets.sh", "add-secret.sh"]

    /// Review gate: any of these tokens inside runtime sources would give the
    /// daemon a process execution, environment export, or direct Keychain
    /// capability. Additions to runtime sources require security review; the
    /// custody seam belongs to a dedicated module in a later issue.
    static let forbiddenRuntimeTokens = [
        "load-secrets.sh",
        "add-secret.sh",
        "find-generic-password",
        "security find",
        "Process(",
        "NSTask",
        "posix_spawn",
        "system(",
        "setenv",
        "putenv",
        "processInfo.environment",
        "import Security",
        "SecItem",
    ]

    @Test("Manifest declares the contracts, daemon, and bootstrap test targets")
    func manifestDeclaresFoundationTargets() {
        #expect(
            BootstrapTestSupport.target(named: "SecretBrokerContracts") != nil,
            "SecretBrokerContracts target missing from Package.swift"
        )
        #expect(
            BootstrapTestSupport.target(named: "SecretBrokerDaemon") != nil,
            "SecretBrokerDaemon target missing from Package.swift"
        )
        #expect(BootstrapTestSupport.target(named: "SecretBrokerBootstrapTests") != nil)
    }

    @Test("Daemon target dependencies are exactly the reviewed allowlist")
    func daemonDependencyAllowlist() throws {
        let daemon = try #require(
            BootstrapTestSupport.target(named: "SecretBrokerDaemon"),
            "SecretBrokerDaemon target missing from Package.swift"
        )
        // SecretBrokerCore admitted deliberately in ARM-24: it holds caller
        // verification and serialized dispatch and depends on contracts only,
        // so it cannot reach custody. Any further entry needs security review.
        #expect(
            BootstrapTestSupport.dependencyNames(of: daemon)
                == ["SecretBrokerContracts", "SecretBrokerCore"]
        )
    }

    @Test("Package resolves no external package dependencies")
    func noExternalPackageDependencies() {
        let dependencies = BootstrapTestSupport.manifestObject()["dependencies"] as? [Any] ?? []
        #expect(dependencies.isEmpty, "foundations must not pull external packages")
    }

    @Test("Legacy scripts are not sources, resources, or plugins of any target")
    func legacyScriptsAreNotTargetInputs() throws {
        let manifestText = try String(
            contentsOf: BootstrapTestSupport.packageRoot.appendingPathComponent("Package.swift"),
            encoding: .utf8
        )
        for script in Self.legacyScripts {
            #expect(!manifestText.contains(script), "Package.swift references \(script)")
        }
        for target in BootstrapTestSupport.manifestTargets() {
            let name = target["name"] as? String ?? "unnamed"
            if let path = target["path"] as? String {
                #expect(
                    path.hasPrefix("Sources") || path.hasPrefix("Tests"),
                    "target \(name) escapes Sources/Tests with path \(path)"
                )
            }
            let resources = target["resources"] as? [[String: Any]] ?? []
            #expect(resources.isEmpty, "target \(name) declares resources; scripts must not ride along")

            // A build tool or command plugin runs arbitrary executables during
            // the build, which would give the scripts a runtime path that the
            // dependency allowlist does not cover.
            let type = target["type"] as? String ?? "regular"
            #expect(
                ["regular", "test"].contains(type),
                "target \(name) has type \(type); plugin targets are not permitted"
            )
            let pluginUsages = target["pluginUsages"] as? [Any] ?? []
            #expect(pluginUsages.isEmpty, "target \(name) declares plugin usages")
        }
    }

    @Test("Package products are exactly the contracts and daemon libraries")
    func productAllowlist() {
        let products = BootstrapTestSupport.manifestObject()["products"] as? [[String: Any]] ?? []
        let names = products.compactMap { $0["name"] as? String }.sorted()
        #expect(
            names == ["SecretBrokerContracts", "SecretBrokerDaemon"],
            "product list changed: \(names). Exporting adapters would make the fakes linkable."
        )
        for product in products {
            let exported = product["targets"] as? [String] ?? []
            #expect(
                !exported.contains("SecretBrokerAdapters"),
                "product \(product["name"] as? String ?? "unnamed") exports the adapters target"
            )
        }
    }

    @Test("Every declared dependency parses, so allowlists cannot pass by omission")
    func dependencyParsingLosesNothing() {
        for target in BootstrapTestSupport.manifestTargets() {
            let name = target["name"] as? String ?? "unnamed"
            let raw = (target["dependencies"] as? [[String: Any]] ?? []).count
            let parsed = BootstrapTestSupport.dependencyNames(of: target).count
            #expect(
                parsed == raw,
                "target \(name) declares \(raw) dependencies but only \(parsed) parsed; an unparsed entry would silently satisfy an allowlist check"
            )
        }
    }

    @Test("Runtime sources exist and cannot reach the export path")
    func runtimeSourcesExcludeExportCapabilities() throws {
        let sources = BootstrapTestSupport.packageRoot.appendingPathComponent("Sources")
        let daemonDir = sources.appendingPathComponent("SecretBrokerDaemon")
        let contractsDir = sources.appendingPathComponent("SecretBrokerContracts")
        #expect(
            FileManager.default.fileExists(atPath: daemonDir.path),
            "Sources/SecretBrokerDaemon missing"
        )
        #expect(
            FileManager.default.fileExists(atPath: contractsDir.path),
            "Sources/SecretBrokerContracts missing"
        )

        for file in BootstrapTestSupport.swiftFiles(under: sources) {
            let text = try String(contentsOf: file, encoding: .utf8)
            for token in Self.forbiddenRuntimeTokens {
                #expect(
                    !text.contains(token),
                    "\(file.lastPathComponent) contains forbidden runtime token: \(token)"
                )
            }
        }
    }
}
