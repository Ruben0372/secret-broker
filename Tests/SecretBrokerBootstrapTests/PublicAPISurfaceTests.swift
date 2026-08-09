import Foundation
import Testing

/// Pins the caller-facing public API surface read from the COMPILED module.
///
/// Why this exists separately from the seam pins: those match declaration
/// forms in source text, so they constrain spelling rather than capability. A
/// sibling protocol refining the custody seam, plus a public static function on
/// the daemon, adds a caller-facing reveal path while emitting zero new
/// undefined symbols and matching none of the source-form patterns. The symbol
/// scan cannot see it either, because it introduces no new import.
///
/// Reading the compiled module's public API closes that gap: anything a caller
/// can reach appears here, whatever form it was declared in.
///
/// Limits: the digest is produced by swift-api-digester against the built
/// module, so it reflects what the current toolchain considers public API.
/// Import lists are excluded deliberately, since they vary with toolchain and
/// are not caller-facing API.
@Suite("Public API surface")
struct PublicAPISurfaceTests {
    static let modules = ["SecretBrokerDaemon", "SecretBrokerContracts"]

    static func goldenAPI(for module: String) throws -> Set<String> {
        let url = BootstrapTestSupport.packageRoot
            .appendingPathComponent("Tests")
            .appendingPathComponent("SecretBrokerBootstrapTests")
            .appendingPathComponent("Golden")
            .appendingPathComponent("\(module).api.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        return Set(
            text
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        )
    }

    /// Runs swift-api-digester over the built module and returns one line per
    /// public declaration, qualified by its enclosing declarations.
    static func observedAPI(for module: String) throws -> Set<String> {
        // Unique per call: suites run in parallel, and a shared path would let
        // one test delete the dump another is still reading.
        let output = FileManager.default.temporaryDirectory
            .appendingPathComponent("secret-broker-api-\(module)-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: output) }

        let sdk = try BootstrapTestSupport.run(["xcrun", "--show-sdk-path"])
            .stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let architecture = try BootstrapTestSupport.run(["uname", "-m"])
            .stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let result = try BootstrapTestSupport.run([
            "xcrun", "swift-api-digester",
            "-dump-sdk",
            "-module", module,
            "-I", BootstrapTestSupport.modulesDirectory.path,
            "-o", output.path,
            "-sdk", sdk,
            "-target", "\(architecture)-apple-macosx14.0",
        ])
        #expect(result.status == 0, "swift-api-digester failed for \(module): \(result.stderr)")

        let data = try Data(contentsOf: output)
        let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        let abiRoot = root["ABIRoot"] as? [String: Any] ?? root

        var declarations: Set<String> = []
        func walk(_ node: [String: Any], path: [String]) {
            let kind = node["kind"] as? String
            let printedName = node["printedName"] as? String
            var childPath = path

            if let kind, let printedName, kind != "Root" {
                // Imports vary by toolchain and are not caller-facing API.
                if kind != "Import" {
                    let declKind = node["declKind"] as? String ?? kind
                    let qualified = (path + [printedName]).joined(separator: ".")
                    declarations.insert("\(declKind) \(qualified)")
                    childPath = path + [printedName]
                }
            }

            for child in node["children"] as? [[String: Any]] ?? [] {
                walk(child, path: childPath)
            }
        }
        walk(abiRoot, path: [])
        return declarations
    }

    @Test("Public API surface matches the reviewed golden file", arguments: modules)
    func apiSurfaceMatchesGolden(module: String) throws {
        let observed = try Self.observedAPI(for: module)
        #expect(
            !observed.isEmpty,
            "no public API read for \(module); the digest found nothing and would pass vacuously"
        )
        let golden = try Self.goldenAPI(for: module)

        let added = observed.subtracting(golden).sorted()
        #expect(
            added.isEmpty,
            """
            NEW PUBLIC API: \(module) exposes \(added.count) declaration(s) absent from the reviewed \
            golden surface: \(added.prefix(20).joined(separator: " | ")). Anything a caller can reach \
            is a security-relevant change, including a protocol refining the custody seam or a static \
            function on the daemon. Regenerating this golden is a reviewed act, never a casual refresh.
            """
        )

        let removed = golden.subtracting(observed).sorted()
        #expect(
            removed.isEmpty,
            """
            STALE GOLDEN: the API surface file for \(module) lists \(removed.count) declaration(s) the \
            module no longer exposes: \(removed.prefix(20).joined(separator: " | ")). The golden file \
            no longer describes this build.
            """
        )
    }

    @Test("API surface pin is wired to the right module and cannot pass empty", arguments: modules)
    func apiPinIsWiredCorrectly(module: String) throws {
        let golden = try Self.goldenAPI(for: module)
        #expect(!golden.isEmpty, "golden API surface for \(module) is empty and would pass anything")

        let observed = try Self.observedAPI(for: module)
        // Anchors that must exist in each module's real surface. If the digest
        // read the wrong module, or produced an empty dump, this fails rather
        // than passing an unpinned surface.
        let anchor = module == "SecretBrokerDaemon" ? "DaemonBootstrap" : "SecretCustodian"
        #expect(
            observed.contains { $0.contains(anchor) },
            "\(module) surface does not mention \(anchor); the digest may have read the wrong module"
        )
        #expect(
            golden.contains { $0.contains(anchor) },
            "golden surface for \(module) does not mention \(anchor); it is not this module's surface"
        )
    }
}
