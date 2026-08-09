import Foundation

/// Anchor type used only to locate this test bundle on disk.
final class TestBundleLocator {}

/// Shared helpers for the bootstrap suite. Tests here inspect the repository
/// and the package manifest instead of production state: no Keychain access,
/// no credentials, no network. Subprocesses are limited to git and swiftpm.
enum BootstrapTestSupport {
    /// Active build directory, derived from where this test bundle actually
    /// lives rather than assuming `.build`. The bundle sits inside whatever
    /// scratch path the build used, so `swift test --scratch-path <dir>` works
    /// without the artifact checks silently finding nothing.
    static let buildDirectory: URL = Bundle(for: TestBundleLocator.self)
        .bundleURL
        .deletingLastPathComponent()

    static var modulesDirectory: URL {
        buildDirectory.appendingPathComponent("Modules")
    }

    /// Canonical identity of the compiler that produced the artifacts: the
    /// Swift version plus the target triple. Symbol sets are only comparable
    /// within one identity, so goldens are keyed by it.
    struct ToolchainIdentity {
        let swiftVersion: String
        let target: String

        /// Filename-safe key, for example swift-6.3.2-arm64-apple-macosx26.0.
        var slug: String { "swift-\(swiftVersion)-\(target)" }
        var description: String { "Apple Swift \(swiftVersion), target \(target)" }
    }

    /// Returns nil when the version output cannot be parsed, so callers fail
    /// loudly rather than guessing an identity.
    static let toolchainIdentity: ToolchainIdentity? = {
        guard let result = try? run(["swift", "--version"]) else { return nil }
        let text = result.stdout + result.stderr

        func firstMatch(_ pattern: String) -> String? {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            guard let match = regex.firstMatch(in: text, range: range),
                  match.numberOfRanges > 1,
                  let captured = Range(match.range(at: 1), in: text)
            else {
                return nil
            }
            return String(text[captured])
        }

        guard let version = firstMatch(#"Apple Swift version ([0-9]+(?:\.[0-9]+)*)"#),
              let target = firstMatch(#"Target:\s*(\S+)"#)
        else {
            return nil
        }
        return ToolchainIdentity(swiftVersion: version, target: target)
    }()

    /// Repository root, derived from this file's location so the suite works
    /// from any working directory, including CI checkouts.
    static let packageRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    struct ProcessResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    @discardableResult
    static func run(_ arguments: [String], workingDirectory: URL = packageRoot) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = arguments
        process.currentDirectoryURL = workingDirectory
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return ProcessResult(
            status: process.terminationStatus,
            stdout: String(decoding: stdoutData, as: UTF8.self),
            stderr: String(decoding: stderrData, as: UTF8.self)
        )
    }

    /// Raw JSON text of the package manifest. Uses a disposable scratch path so
    /// the dump never contends with the .build directory of the running tests.
    static let manifestDumpText: String = {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("secret-broker-manifest-scratch-\(ProcessInfo.processInfo.processIdentifier)")
        defer { try? FileManager.default.removeItem(at: scratch) }
        guard let result = try? run([
            "swift", "package",
            "--package-path", packageRoot.path,
            "--scratch-path", scratch.path,
            "dump-package",
        ]), result.status == 0 else {
            return ""
        }
        return result.stdout
    }()

    static func manifestObject() -> [String: Any] {
        guard let data = manifestDumpText.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return [:]
        }
        return object
    }

    static func manifestTargets() -> [[String: Any]] {
        manifestObject()["targets"] as? [[String: Any]] ?? []
    }

    static func target(named name: String) -> [String: Any]? {
        manifestTargets().first { ($0["name"] as? String) == name }
    }

    static func dependencyNames(of target: [String: Any]) -> [String] {
        guard let dependencies = target["dependencies"] as? [[String: Any]] else {
            return []
        }
        return dependencies.compactMap { dependency in
            for key in ["byName", "target", "product"] {
                if let value = dependency[key] as? [Any], let name = value.first as? String {
                    return name
                }
            }
            return nil
        }
    }

    static func swiftFiles(under directory: URL) -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }
        return enumerator.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
    }
}
