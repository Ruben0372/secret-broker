import CryptoKit
import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerCore
@testable import SecretBrokerDaemon
import Testing

/// A receipt digest is not a privacy control if it is an unkeyed hash of a
/// low-entropy reference: the reference space is small enough to enumerate, so
/// an unsalted digest is reversible by wordlist. The digest must be keyed with
/// a per-boot secret that never leaves memory, which keeps receipts correlatable
/// within a boot while making them meaningless outside it.
@Suite("Receipt digest keying")
struct DigestKeyingTests {
    static func unsaltedSHA256(namespace: String, name: String) -> String {
        let canonical = "\(namespace)\u{1F}\(name)"
        return SHA256.hash(data: Data(canonical.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    @Test("Digests stay stable for one daemon so receipts correlate")
    func stableWithinOneDaemon() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]), verifier: TestCaller.verifier)
        let first = try #require(await daemon.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        let second = try #require(await daemon.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        #expect(first.requestDigest == second.requestDigest)
    }

    @Test("Two daemons in one process share the key and correlate")
    func correlatesAcrossInstancesInOneProcess() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let first = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]), verifier: TestCaller.verifier)
        let second = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]), verifier: TestCaller.verifier)
        let fromFirst = try #require(await first.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        let fromSecond = try #require(await second.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        #expect(
            fromFirst.requestDigest == fromSecond.requestDigest,
            "the receipt key is per instance, not process-wide; receipts should correlate within a process lifetime"
        )
    }

    @Test("The key factory is random, so a restart is unlinkable")
    func keyFactoryIsRandom() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        // Two generated keys stand in for two process lifetimes: the process
        // key comes from this same factory at first access.
        let oneLife = DaemonBootstrap(
            custodian: InMemorySecretCustodian(known: [reference]),
            verifier: TestCaller.verifier,
            receiptKey: ReceiptKeyStore.makeKey()
        )
        let nextLife = DaemonBootstrap(
            custodian: InMemorySecretCustodian(known: [reference]),
            verifier: TestCaller.verifier,
            receiptKey: ReceiptKeyStore.makeKey()
        )
        let fromOne = try #require(await oneLife.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        let fromNext = try #require(await nextLife.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        #expect(
            fromOne.requestDigest != fromNext.requestDigest,
            "the key factory returns a fixed key, so receipts would link across restarts"
        )
    }

    @Test("The process key is runtime-generated, not a fixed constant")
    func processKeyIsRuntimeGenerated() throws {
        let processKeyBytes = ReceiptKeyStore.processKey.withUnsafeBytes { Data($0) }
        #expect(processKeyBytes.count == 32)
        // A compile-time constant would be a fixed pattern; a random key is
        // neither all zero nor equal to a freshly generated one.
        #expect(processKeyBytes != Data(repeating: 0, count: 32))
        let freshBytes = ReceiptKeyStore.makeKey().withUnsafeBytes { Data($0) }
        #expect(processKeyBytes != freshBytes)
    }

    @Test("Digest is not the unsalted hash of the reference")
    func notUnsaltedHash() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]), verifier: TestCaller.verifier)
        let receipt = try #require(await daemon.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        #expect(
            receipt.requestDigest != Self.unsaltedSHA256(namespace: "test", name: "FAKE_A"),
            "digest equals the unsalted SHA256 of the reference and is reversible by wordlist"
        )
    }

    @Test("Encoded receipt carries no key, salt, or nonce field")
    func receiptCarriesNoKeyMaterial() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]), verifier: TestCaller.verifier)
        let receipt = try #require(await daemon.dispatch(.availability(reference), from: TestCaller.identity).receipt)
        let data = try JSONEncoder().encode(receipt)
        let object = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(Set(object.keys) == ["requestDigest", "resultClass"])
        for field in object.keys {
            let lowered = field.lowercased()
            #expect(!lowered.contains("key"))
            #expect(!lowered.contains("salt"))
            #expect(!lowered.contains("nonce"))
            #expect(!lowered.contains("secret"))
        }
        // Without a key, salt, or nonce on the wire, a receipt cannot be
        // replayed against the digest offline even by its own recipient.
        let encoded = String(decoding: data, as: UTF8.self).lowercased()
        #expect(!encoded.contains("salt"))
        #expect(!encoded.contains("nonce"))
    }

    @Test("Distinct references still separate within one boot")
    func distinctReferencesSeparate() async throws {
        let present = try SecretReference(namespace: "test", name: "FAKE_A")
        let other = try SecretReference(namespace: "test", name: "FAKE_B")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [present]), verifier: TestCaller.verifier)
        let first = try #require(await daemon.dispatch(.availability(present), from: TestCaller.identity).receipt)
        let second = try #require(await daemon.dispatch(.availability(other), from: TestCaller.identity).receipt)
        #expect(first.requestDigest != second.requestDigest)
        #expect(first.requestDigest.count == 64)
        #expect(second.requestDigest.count == 64)
    }
}
