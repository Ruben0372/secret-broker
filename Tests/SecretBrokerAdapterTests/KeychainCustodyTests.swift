import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import Testing

/// Isolated Keychain custody.
///
/// The acceptance property is negative and therefore has to be hunted rather
/// than asserted in passing: no secret value may appear in the environment, in
/// logs, in receipts, in error strings, or in anything returned to Armel-facing
/// code. The adapter hands back opaque handles and nothing else.
///
/// Every leak check scans for the secret VALUE, never for its name. Searching
/// for the name would pass while the value sat beside it, which is the shape of
/// a check that looks thorough and tests nothing.
///
/// The whole suite runs against a disposable namespace with an in-memory
/// backing. Production access-group activation is held OFF, and that is
/// asserted rather than assumed.

/// Every rendering of a secret that a surface could plausibly expose.
///
/// The original scan matched one rendering, the UTF-8 text form, against six
/// surfaces. A surface exposing the same bytes any other way was invisible to
/// it: an array of decimal bytes, a hex dump, a base64 blob. The value is just
/// as recoverable in all of those, so matching one spelling was a guard that
/// looked thorough and covered a quarter of the ground.
///
/// A raw byte-sequence search subsumes the text form only, since the other
/// renderings are different bytes on the surface. So this does both: the raw
/// subsequence AND each textual rendering, explicitly named so coverage is
/// legible rather than implied.
struct LeakScanner {
    let secret: [UInt8]

    var text: String { String(decoding: secret, as: UTF8.self) }
    var decimalSpaced: String { "[" + secret.map(String.init).joined(separator: ", ") + "]" }
    var decimalTight: String { "[" + secret.map(String.init).joined(separator: ",") + "]" }
    var hexLower: String { secret.map { String(format: "%02x", $0) }.joined() }
    var hexUpper: String { secret.map { String(format: "%02X", $0) }.joined() }
    var base64: String { Data(secret).base64EncodedString() }

    /// Named renderings, so a failure says WHICH spelling was found.
    var renderings: [(name: String, value: String)] {
        [
            ("text", text),
            ("decimal-spaced", decimalSpaced),
            ("decimal-tight", decimalTight),
            ("hex-lower", hexLower),
            ("hex-upper", hexUpper),
            ("base64", base64),
        ]
    }

    /// Findings for one surface, empty when clean.
    func findings(in surface: String, named label: String) -> [String] {
        var found: [String] = []
        // Raw byte subsequence over the surface's own bytes.
        if Self.contains(Array(surface.utf8), subsequence: secret) {
            found.append("\(label): raw byte sequence")
        }
        for rendering in renderings where surface.contains(rendering.value) {
            found.append("\(label): \(rendering.name)")
        }
        return found
    }

    static func contains(_ haystack: [UInt8], subsequence needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for start in 0...(haystack.count - needle.count)
        where Array(haystack[start..<(start + needle.count)]) == needle {
            return true
        }
        return false
    }
}

@Suite("Keychain custody, leak and boundary proofs")
struct KeychainCustodyTests {
    /// A value chosen to be unmistakable in any haystack. If this string turns
    /// up anywhere it should not, the match is the finding, not a coincidence.
    static let secretValue = "ARM26-SECRET-VALUE-e3f1a7c9d24b-DO-NOT-LEAK"
    static let secretName = "FAKE_API_KEY"

    static func disposableNamespace(_ label: String = #function) -> String {
        "arm26.disposable.\(label).\(UUID().uuidString)"
    }

    static func makeStore(namespace: String) -> (KeychainStore, InMemoryKeychainBacking) {
        let backing = InMemoryKeychainBacking()
        let store = KeychainStore(
            namespace: namespace,
            backing: backing,
            accessGroup: KeychainStore.disposableTestAccessGroup
        )
        return (store, backing)
    }

    // MARK: The acceptance property

    @Test("No secret value reaches any surface, in any rendering")
    func nothingLeaksTheSecretValue() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var recorder = CustodyLogRecorder()
        let scanner = LeakScanner(secret: Array(Self.secretValue.utf8))

        let handle = try store.store(
            secret: Array(Self.secretValue.utf8),
            named: Self.secretName,
            log: &recorder
        )

        var refusalMessage = ""
        do {
            _ = try store.store(secret: Array(Self.secretValue.utf8), named: "", log: &recorder)
            Issue.record("an empty name was accepted")
        } catch let refusal as CustodyRefusal {
            refusalMessage = refusal.message + String(describing: refusal)
        }

        // The six surfaces, gathered so every one goes through the SAME scan.
        // Scanning them by hand invited exactly the divergence that let one
        // surface be checked for one spelling.
        var surfaces: [(String, String)] = [
            ("handle", String(describing: handle)),
            ("logs", recorder.lines.joined(separator: "\n")),
            ("receipt", String(describing: store.receipt(for: handle))),
            ("refusal", refusalMessage),
            ("backing-caller-visible", backing.callerVisibleDescription),
        ]
        surfaces.append(
            ("environment", ProcessInfo.processInfo.environment.map { "\($0.key)=\($0.value)" }
                .joined(separator: "\n"))
        )
        #expect(surfaces.count == 6, "expected six surfaces, gathered \(surfaces.count)")

        var findings: [String] = []
        for (label, surface) in surfaces {
            findings += scanner.findings(in: surface, named: label)
        }
        #expect(findings.isEmpty, "the secret is recoverable: \(findings)")

        // POSITIVE CONTROLS: the scans ran against real, populated surfaces.
        #expect(store.exists(handle), "the secret was never stored, so nothing above was tested")
        #expect(backing.rawItemCount == 1, "expected exactly one stored item")
        #expect(!recorder.lines.isEmpty, "nothing was logged, so that surface proved nothing")
        #expect(!refusalMessage.isEmpty, "no refusal was produced, so that surface proved nothing")
    }

    /// The control, widened. Planting into one surface proved that one surface
    /// could be read; it said nothing about the other five, and nothing about
    /// any rendering but the text form.
    @Test("The scan detects every rendering planted into every surface")
    func leakScanIsNotVacuous() {
        let scanner = LeakScanner(secret: Array(Self.secretValue.utf8))
        let surfaceLabels = [
            "handle", "logs", "receipt", "refusal", "backing-caller-visible", "environment",
        ]
        #expect(surfaceLabels.count == 6)

        var undetected: [String] = []
        var checks = 0
        for label in surfaceLabels {
            for rendering in scanner.renderings {
                // A surface shaped like the real one, carrying the rendering.
                let planted = "\(label)(namespace/FAKE_API_KEY: \(rendering.value))"
                if scanner.findings(in: planted, named: label).isEmpty {
                    undetected.append("\(label)/\(rendering.name)")
                }
                checks += 1
            }
        }
        #expect(undetected.isEmpty, "the scan cannot see: \(undetected)")
        #expect(checks == 36, "expected 6 surfaces times 6 renderings, ran \(checks)")

        // And the scan does not fire on a surface that carries no secret, so it
        // is a detector rather than an alarm that is always on.
        #expect(
            scanner.findings(in: "handle(namespace/FAKE_API_KEY#1)", named: "handle").isEmpty,
            "the scan reported a finding on a clean surface"
        )
    }

    // MARK: The seven boundary cases, each with a positive control

    @Test("Access-group mismatch is refused, and the matching group is accepted")
    func accessGroupMismatch() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let handle = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        let foreign = KeychainStore(
            namespace: namespace,
            backing: backing,
            accessGroup: "com.example.some-other-group"
        )
        #expect(throws: CustodyRefusal.self) { try foreign.resolve(handle) }

        // POSITIVE CONTROL: the correct group still resolves it.
        #expect(throws: Never.self) { try store.resolve(handle) }
    }

    @Test("The custody surface exposes no way to read secret bytes back")
    func nonExportability() throws {
        let namespace = Self.disposableNamespace()
        let (store, _) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let handle = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        // Structural, not behavioural: the item is marked non-exportable and
        // the handle type has no member that could carry a value.
        #expect(store.isNonExportable(handle), "the stored item is not marked non-exportable")
        let mirror = Mirror(reflecting: handle)
        for child in mirror.children {
            #expect(
                !String(describing: child.value).contains(Self.secretValue),
                "handle field \(child.label ?? "?") carries the value"
            )
        }

        // POSITIVE CONTROL: the handle still resolves to a live item, so
        // non-exportability is not just an unusable store.
        #expect(throws: Never.self) { try store.resolve(handle) }
    }

    @Test("Overwrite supersedes the old handle, and the new one works")
    func overwrite() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let first = try store.store(secret: Array("first-value".utf8), named: Self.secretName, log: &log)
        let second = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        #expect(first != second, "overwrite returned the same handle, so supersession is invisible")
        #expect(second.generation > first.generation, "the generation did not advance on overwrite")
        #expect(throws: CustodyRefusal.self) { try store.resolve(first) }
        #expect(backing.rawItemCount == 1, "overwrite left a second copy behind")

        // POSITIVE CONTROL: the current handle resolves.
        #expect(throws: Never.self) { try store.resolve(second) }
    }

    @Test("Deletion makes the handle unresolvable and leaves no residue")
    func deletion() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let handle = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        try store.delete(handle)
        #expect(throws: CustodyRefusal.self) { try store.resolve(handle) }
        #expect(backing.rawItemCount == 0, "deletion left an item behind")
        #expect(
            !backing.residueDescription.contains(Self.secretValue),
            "the deleted value is still present in the backing"
        )

        // POSITIVE CONTROL: storing again after deletion works, so delete did
        // not simply break the store.
        #expect(throws: Never.self) {
            _ = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)
        }
    }

    @Test("A handle survives a restart of the store but not of the namespace")
    func restart() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let handle = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        // A fresh store over the same backing and namespace still resolves it.
        let restarted = KeychainStore(
            namespace: namespace,
            backing: backing,
            accessGroup: KeychainStore.disposableTestAccessGroup
        )
        #expect(throws: Never.self) { try restarted.resolve(handle) }

        // A different namespace does not, even with the same backing: a handle
        // is scoped, not a bearer token.
        let otherNamespace = KeychainStore(
            namespace: Self.disposableNamespace("other"),
            backing: backing,
            accessGroup: KeychainStore.disposableTestAccessGroup
        )
        #expect(throws: CustodyRefusal.self) { try otherNamespace.resolve(handle) }
    }

    @Test("A handle from a foreign store is refused")
    func foreignRestore() throws {
        let namespace = Self.disposableNamespace()
        let (store, _) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let mine = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)

        // A handle minted elsewhere, over a different backing, as a restored
        // backup would be. Same shape, different origin.
        let (foreignStore, _) = Self.makeStore(namespace: Self.disposableNamespace("foreign"))
        let foreign = try foreignStore.store(
            secret: Array("some-other-value".utf8), named: Self.secretName, log: &log
        )
        #expect(throws: CustodyRefusal.self) { try store.resolve(foreign) }

        // POSITIVE CONTROL: my own handle still resolves in my own store.
        #expect(throws: Never.self) { try store.resolve(mine) }
    }

    @Test("Refusals and logs redact, naming the item without revealing it")
    func redaction() throws {
        let namespace = Self.disposableNamespace()
        let (store, _) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        let handle = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)
        try store.delete(handle)

        do {
            _ = try store.resolve(handle)
            Issue.record("a deleted handle resolved")
        } catch let refusal as CustodyRefusal {
            #expect(!refusal.message.contains(Self.secretValue), "the refusal reveals the value")
            // POSITIVE CONTROL for redaction: it is still USEFUL. A message
            // that redacted everything would also pass a leak scan and help
            // nobody diagnose anything.
            #expect(
                refusal.message.contains(Self.secretName) || refusal.message.contains("not found"),
                "the refusal is so redacted it identifies nothing: \(refusal.message)"
            )
        }
    }

    // MARK: The production boundary

    @Test("Production access-group activation is OFF and refuses")
    func productionActivationIsDisabled() {
        #expect(
            KeychainStore.isProductionAccessGroupEnabled == false,
            "production access-group activation is enabled; it must stay off until release signing"
        )
        #expect(
            KeychainStore.productionActivationGate.contains("release signing"),
            "the gate does not state what it waits on"
        )
        #expect(throws: CustodyRefusal.self) {
            _ = try KeychainStore.productionStore(namespace: "arm26.production.attempt")
        }
    }

    @Test("The disposable namespace is cleaned with no residue")
    func disposableNamespaceCleansUp() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var log = CustodyLogRecorder()
        _ = try store.store(secret: Array(Self.secretValue.utf8), named: Self.secretName, log: &log)
        _ = try store.store(secret: Array("second".utf8), named: "OTHER_FAKE", log: &log)
        #expect(backing.rawItemCount == 2)

        try store.destroyDisposableNamespace()
        #expect(backing.rawItemCount == 0, "cleanup left items behind")
        #expect(
            !backing.residueDescription.contains(Self.secretValue),
            "cleanup left the value recoverable in the backing"
        )
    }
}
