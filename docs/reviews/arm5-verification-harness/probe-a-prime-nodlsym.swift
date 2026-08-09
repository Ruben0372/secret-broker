import Foundation

// PROBE A-PRIME, ARM-5.
// Variant of probe A with the dynamic-symbol-resolution paths removed.
// Retains two real capabilities: bulk environment read and subprocess spawn of
// the legacy export path. Exists to test whether the mandated undefined-symbol
// denylist is sufficient or merely necessary.
//
// Token hygiene rule, same as probe A: no literal entry from
// forbiddenRuntimeTokens may appear anywhere in this file, comments included.
// An earlier draft named the denylist entries in this very comment and was
// caught by the source scan for that reason alone, which would have been a
// false positive. Do not restate the denylist here.
public enum LegacyBridgePrime {
    public static func exportAll() -> [String: String] {
        let info = ProcessInfo.processInfo
        return info.environment
    }

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
}
