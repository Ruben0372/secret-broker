import Foundation
import Testing

/// Capability assertion at the artifact level rather than the source level.
///
/// A source-token denylist loses to obfuscation by construction: the same
/// capability can be spelled through a computed selector, a dynamic lookup, or
/// a helper in another file. What the linker records cannot be spelled away, so
/// this suite reads the undefined symbols the compiled daemon actually imports.
///
/// Residual limit, stated plainly: this is a denylist of named symbols, so it
/// catches the listed families and nothing else. Capabilities reached through
/// already-linked Foundation surfaces, ProcessInfo environment access being the
/// clearest example, resolve inside Foundation and do not appear here. This
/// raises the cost of an obfuscated capability; it does not make the boundary
/// airtight.
@Suite("Artifact capability")
struct ArtifactCapabilityTests {
    /// Matched as prefixes, so variants such as posix_spawnp and the SecItem
    /// and SecKeychain families are covered too.
    static let forbiddenSymbolPrefixes = [
        "dlopen",
        "dlsym",
        "posix_spawn",
        "execve",
        "setenv",
        "putenv",
        "SecItem",
        "SecKeychain",
    ]

    /// Compiled objects for the daemon module. find does not follow symlinks by
    /// default, so the .build/debug alias does not produce duplicates.
    static func daemonArtifacts() throws -> [String] {
        let objects = try BootstrapTestSupport.run([
            "find", ".build",
            "-name", "*.o",
            "-path", "*SecretBrokerDaemon.build*",
        ])
        let archives = try BootstrapTestSupport.run([
            "find", ".build",
            "-name", "libSecretBrokerDaemon*.a",
        ])
        return (objects.stdout + archives.stdout)
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    static func undefinedSymbols(in artifacts: [String]) throws -> [String] {
        let result = try BootstrapTestSupport.run(["nm", "-u"] + artifacts)
        #expect(result.status == 0, "nm failed: \(result.stderr)")
        return result.stdout
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            // Drop blank lines and the "path:" headers nm prints per file.
            .filter { !$0.isEmpty && !$0.hasSuffix(":") }
            .map { symbol in
                var symbol = symbol
                if symbol.hasPrefix("_") { symbol.removeFirst() }
                return symbol
            }
    }

    @Test("Daemon artifact imports no dynamic loading, process, environment, or Keychain symbol")
    func daemonArtifactCapabilities() throws {
        let artifacts = try Self.daemonArtifacts()
        #expect(
            !artifacts.isEmpty,
            "no compiled SecretBrokerDaemon artifacts found under .build; the daemon must be built before this assertion means anything"
        )
        let symbols = try Self.undefinedSymbols(in: artifacts)
        #expect(!symbols.isEmpty, "nm reported no undefined symbols, which means the scan read nothing")

        for symbol in symbols {
            for prefix in Self.forbiddenSymbolPrefixes {
                #expect(
                    !symbol.hasPrefix(prefix),
                    "daemon artifact imports \(symbol), matching forbidden family \(prefix)"
                )
            }
        }
    }

    @Test("Symbol scan reads the daemon module and would see a real import")
    func scanIsWiredToTheRightArtifacts() throws {
        let artifacts = try Self.daemonArtifacts()
        #expect(
            artifacts.contains { $0.contains("SecretBrokerDaemon") },
            "artifact list does not include the daemon module: \(artifacts)"
        )
        let symbols = try Self.undefinedSymbols(in: artifacts)
        // Proves the pipeline parses real symbols rather than an empty set: the
        // daemon genuinely imports CryptoKit for the keyed receipt digest.
        #expect(
            symbols.contains { $0.contains("CryptoKit") },
            "expected CryptoKit imports in the daemon artifact; the scan may be reading the wrong files"
        )
    }
}
