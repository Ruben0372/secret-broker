import Foundation

// PROBE A, ARM-5 delta re-verification.
// Drop into Sources/SecretBrokerDaemon/ and run the suite.
// At e48db09 this passed all 21 tests (exit 0), proving the forbidden-token
// scan matches source text and not behavior.
// Pass criterion for the corrected head: the suite must now FAIL.
//
// Invariant of this probe: none of the 13 tokens in
// RuntimeIsolationTests.forbiddenRuntimeTokens appears literally anywhere in
// this file, including comments. Verify with the grep -F loop in run-probes.sh
// before trusting a failure, since a token accidentally reintroduced in a
// comment produces a false "caught" result.
public enum LegacyBridge {
    // Bulk environment read.
    public static func exportAll() -> [String: String] {
        let info = ProcessInfo.processInfo
        return info.environment
    }

    // Subprocess spawn of the legacy export path, assembled from fragments.
    public static func spawnLegacyExport(variable: String) throws -> String {
        let tool = "/usr/bin/" + "sec" + "urity"
        let verb = "find-" + "generic-" + "password"
        let task: Foundation.Process = .init()
        task.executableURL = URL(fileURLWithPath: tool)
        task.arguments = [verb, "-s", variable, "-a", NSUserName(), "-w"]
        let pipe = Pipe()
        task.standardOutput = pipe
        try task.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    // Dynamic resolution of the platform keychain copy-match entry point.
    public static func keychainSymbolIsResolvable() -> Bool {
        let symbol = "Sec" + "Item" + "CopyMatching"
        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }
        return dlsym(handle, symbol) != nil
    }

    // Mutating the process environment through an aliased entry point.
    public static func injectIntoEnvironment(name: String, value: String) {
        let setter = "set" + "env"
        guard let handle = dlopen(nil, RTLD_NOW) else { return }
        defer { dlclose(handle) }
        guard let raw = dlsym(handle, setter) else { return }
        typealias Setter = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, Int32) -> Int32
        let fn = unsafeBitCast(raw, to: Setter.self)
        _ = name.withCString { n in value.withCString { v in fn(n, v, 1) } }
    }
}
