import Foundation
import Testing

/// Capability assertion at the artifact level rather than the source level.
///
/// A source-token denylist loses to obfuscation by construction: the same
/// capability can be spelled through a computed selector, a dynamic lookup, or
/// a helper in another file. What the linker records is harder to spell away,
/// so this suite reads the undefined symbols the compiled modules import.
///
/// Two layers, because they fail differently:
/// - The golden allowlist notices anything new. It is the layer that catches a
///   capability nobody thought to name in advance.
/// - The denylist names known-bad families and produces a readable failure, so
///   a reviewer sees what was reached for rather than a symbol set diff.
///
/// Honest limits. This check is macOS and Objective-C interop specific. The
/// stable signal is the `_OBJC_CLASS_$_` class reference, which appears when a
/// module touches a Foundation class; selector stubs are not the primary signal
/// and are not relied on here. The residual limit is capability reachable
/// through APIs the module already legitimately links, which by definition
/// introduces no new symbol. This raises the cost of an obfuscated capability
/// and narrows what can be added unnoticed. It is not airtight.
@Suite("Artifact capability")
struct ArtifactCapabilityTests {
    static let modules = ["SecretBrokerDaemon", "SecretBrokerContracts"]

    /// Needles are assembled from fragments at run time so that neither the
    /// source token scan nor any future text scan can false-positive on this
    /// file's own contents. AdaptersBoundaryTests uses the same pattern.
    static var forbiddenNeedles: [String] {
        let dynamicLoader = "dl"
        let security = "Sec"
        let objcClass = "_OBJC" + "_CLASS_$_"
        return [
            dynamicLoader + "open",
            dynamicLoader + "sym",
            "posix" + "_spawn",
            "exe" + "cve",
            "set" + "env",
            "put" + "env",
            security + "Item",
            security + "Keychain",
            objcClass + "NS" + "Task",
            objcClass + "NS" + "ProcessInfo",
        ]
    }

    static func artifacts(for module: String) throws -> [String] {
        let objects = try BootstrapTestSupport.run([
            "find", ".build",
            "-name", "*.o",
            "-path", "*\(module).build*",
        ])
        let archives = try BootstrapTestSupport.run([
            "find", ".build",
            "-name", "lib\(module)*.a",
        ])
        return (objects.stdout + archives.stdout)
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    static func undefinedSymbols(for module: String) throws -> [String] {
        let files = try artifacts(for: module)
        guard !files.isEmpty else { return [] }
        let result = try BootstrapTestSupport.run(["nm", "-u"] + files)
        #expect(result.status == 0, "nm failed for \(module): \(result.stderr)")
        return result.stdout
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            // Drop blank lines and the "path:" header nm prints per file.
            .filter { !$0.isEmpty && !$0.hasSuffix(":") }
    }

    static func goldenSymbols(for module: String) throws -> Set<String> {
        let url = BootstrapTestSupport.packageRoot
            .appendingPathComponent("Tests")
            .appendingPathComponent("SecretBrokerBootstrapTests")
            .appendingPathComponent("Golden")
            .appendingPathComponent("\(module).symbols.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        return Set(
            text
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        )
    }

    @Test("Every undefined symbol is in the reviewed golden allowlist", arguments: modules)
    func symbolsStayWithinGoldenAllowlist(module: String) throws {
        let symbols = try Self.undefinedSymbols(for: module)
        #expect(
            !symbols.isEmpty,
            "no undefined symbols read for \(module); the scan found nothing and would pass vacuously"
        )
        let golden = try Self.goldenSymbols(for: module)
        #expect(!golden.isEmpty, "golden allowlist for \(module) is empty")

        let unexpected = Set(symbols).subtracting(golden).sorted()
        #expect(
            unexpected.isEmpty,
            """
            \(module) imports \(unexpected.count) symbol(s) absent from the reviewed golden allowlist: \
            \(unexpected.prefix(20).joined(separator: ", ")). \
            If this is an intended dependency change, regenerating the golden file is a reviewed act \
            under the pinned CI toolchain, reviewed symbol by symbol, never a casual refresh.
            """
        )
    }

    @Test("No known-bad capability symbol appears in either module", arguments: modules)
    func noForbiddenCapabilitySymbols(module: String) throws {
        let symbols = try Self.undefinedSymbols(for: module)
        #expect(!symbols.isEmpty, "no undefined symbols read for \(module)")

        for symbol in symbols {
            for needle in Self.forbiddenNeedles where symbol.contains(needle) {
                Issue.record(
                    """
                    \(module) imports \(symbol), which matches the forbidden capability family \
                    \(needle). This module must not reach dynamic loading, process spawning, \
                    environment mutation, or Keychain APIs.
                    """
                )
            }
        }
    }

    @Test("Symbol scan is wired to real artifacts", arguments: modules)
    func scanReadsRealArtifacts(module: String) throws {
        let files = try Self.artifacts(for: module)
        #expect(
            !files.isEmpty,
            "no compiled \(module) artifacts found under .build; build the package before this assertion means anything"
        )
        #expect(files.contains { $0.contains(module) })
        let symbols = try Self.undefinedSymbols(for: module)
        // Proves the pipeline parses real symbols rather than an empty set.
        #expect(
            symbols.contains { $0.contains("Swift") || $0.contains("Foundation") },
            "expected stdlib or Foundation imports in \(module); the scan may be reading the wrong files"
        )
    }
}
