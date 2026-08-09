import Foundation

// PROBE E, ARM-5.
// Tests the drift classifier rather than the golden layer.
//
// classify() sends any symbol beginning "_$s" to .toolchainDrift, whose message
// states these classes "carry no capability" and steers the reader toward
// confirming the identity key before regenerating. But "_$s" is the Swift
// mangling prefix for ANY Swift declaration reference, not only runtime
// plumbing. A capability expressed through a Swift-native API emits mangled
// symbols and no Objective-C class reference.
//
// This reads an arbitrary file from disk, a real capability for a credential
// custodian, using only Swift-native Foundation value types. No needle from
// forbiddenNeedles appears here, in code or comment.
public enum NativeReader {
    /// Arbitrary filesystem read, including any credential file the daemon's
    /// user can open.
    public static func read(path: String) -> Data? {
        let url = URL(fileURLWithPath: path)
        return try? Data(contentsOf: url)
    }

    /// Arbitrary write, so material can leave the process without a subprocess
    /// or a network call.
    public static func write(_ payload: Data, to path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        do {
            try payload.write(to: url, options: [.atomic])
            return true
        } catch {
            return false
        }
    }
}
