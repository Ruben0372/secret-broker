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

    @Test("No secret value reaches the environment, a log, a receipt, an error, or a result")
    func nothingLeaksTheSecretValue() throws {
        let namespace = Self.disposableNamespace()
        let (store, backing) = Self.makeStore(namespace: namespace)
        var recorder = CustodyLogRecorder()

        let handle = try store.store(
            secret: Array(Self.secretValue.utf8),
            named: Self.secretName,
            log: &recorder
        )

        // 1. The returned handle.
        let handleDescription = String(describing: handle)
        #expect(!handleDescription.contains(Self.secretValue), "the handle's description carries the value")

        // 2. Every log line the operation emitted.
        for line in recorder.lines {
            #expect(!line.contains(Self.secretValue), "a log line carries the value: \(line)")
        }
        #expect(!recorder.lines.isEmpty, "nothing was logged, so this scan proved nothing")

        // 3. The receipt.
        let receipt = store.receipt(for: handle)
        #expect(!String(describing: receipt).contains(Self.secretValue), "the receipt carries the value")

        // 4. Error strings, from a refusal on the same secret.
        do {
            _ = try store.store(secret: Array(Self.secretValue.utf8), named: "", log: &recorder)
            Issue.record("an empty name was accepted")
        } catch let refusal as CustodyRefusal {
            #expect(!refusal.message.contains(Self.secretValue), "a refusal message carries the value")
            #expect(!String(describing: refusal).contains(Self.secretValue))
        }

        // 5. The process environment, which the adapter must never touch.
        for (key, value) in ProcessInfo.processInfo.environment {
            #expect(!value.contains(Self.secretValue), "environment variable \(key) carries the value")
        }

        // 6. Everything the backing exposes to a caller that is not custody.
        #expect(
            !backing.callerVisibleDescription.contains(Self.secretValue),
            "the backing's caller-visible surface carries the value"
        )

        // POSITIVE CONTROL: the item really was stored, so the scans above ran
        // against a populated store rather than an empty one.
        #expect(store.exists(handle), "the secret was never stored, so nothing above was actually tested")
        #expect(backing.rawItemCount == 1, "expected exactly one stored item")
    }

    /// The scan must be capable of finding the value. A leak hunt that cannot
    /// detect a planted leak is decoration.
    @Test("The leak scan detects a planted value, so it is not vacuous")
    func leakScanIsNotVacuous() {
        var recorder = CustodyLogRecorder()
        recorder.record("this line deliberately contains \(Self.secretValue) as a control")
        let found = recorder.lines.contains { $0.contains(Self.secretValue) }
        #expect(found, "the recorder cannot see a value planted directly in it")
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
