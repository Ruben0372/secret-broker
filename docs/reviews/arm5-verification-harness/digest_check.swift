import CryptoKit
import Foundation

// Verbatim copy of DaemonBootstrap.digest(of:) logic, to confirm the Python
// mirror used in the reversibility demonstration matches the real output.
func digest(namespace: String, name: String) -> String {
    let canonical = "\(namespace)\u{1F}\(name)"
    let hash = SHA256.hash(data: Data(canonical.utf8))
    return hash.map { String(format: "%02x", $0) }.joined()
}

print(digest(namespace: "prod", name: "OPENAI_API_KEY"))
