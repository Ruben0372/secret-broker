import CryptoKit
import Foundation
import SecretBrokerAdapters
import SecretBrokerContracts
import SecretBrokerDaemon
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

    @Test("Digests stay stable within one boot so receipts correlate")
    func stableWithinBoot() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]))
        let first = await daemon.handle(.availability(reference))
        let second = await daemon.handle(.availability(reference))
        #expect(first.requestDigest == second.requestDigest)
    }

    @Test("The same reference digests differently across boots")
    func differsAcrossBoots() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let bootOne = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]))
        let bootTwo = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]))
        let fromFirst = await bootOne.handle(.availability(reference))
        let fromSecond = await bootTwo.handle(.availability(reference))
        #expect(
            fromFirst.requestDigest != fromSecond.requestDigest,
            "digest is not keyed per boot, so it is recoverable by enumerating references"
        )
    }

    @Test("Digest is not the unsalted hash of the reference")
    func notUnsaltedHash() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]))
        let receipt = await daemon.handle(.availability(reference))
        #expect(
            receipt.requestDigest != Self.unsaltedSHA256(namespace: "test", name: "FAKE_A"),
            "digest equals the unsalted SHA256 of the reference and is reversible by wordlist"
        )
    }

    @Test("Encoded receipt carries no key, salt, or nonce field")
    func receiptCarriesNoKeyMaterial() async throws {
        let reference = try SecretReference(namespace: "test", name: "FAKE_A")
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [reference]))
        let receipt = await daemon.handle(.availability(reference))
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
        let daemon = DaemonBootstrap(custodian: InMemorySecretCustodian(known: [present]))
        let first = await daemon.handle(.availability(present))
        let second = await daemon.handle(.availability(other))
        #expect(first.requestDigest != second.requestDigest)
        #expect(first.requestDigest.count == 64)
        #expect(second.requestDigest.count == 64)
    }
}
