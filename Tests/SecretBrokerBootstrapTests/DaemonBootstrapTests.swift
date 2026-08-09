import Foundation
import SecretBrokerContracts
import SecretBrokerDaemon
import Testing

/// In-memory custodian: disposable state only, no Keychain, no credentials.
struct FakeSecretCustodian: SecretCustodian {
    let known: Set<SecretReference>

    func availability(of reference: SecretReference) async throws -> SecretAvailability {
        known.contains(reference) ? .present : .absent
    }
}

struct FailingCustodian: SecretCustodian {
    struct ProbeFailure: Error {}

    func availability(of reference: SecretReference) async throws -> SecretAvailability {
        throw ProbeFailure()
    }
}

@Suite("Daemon bootstrap with fakes")
struct DaemonBootstrapTests {
    @Test("Bootstrap reports version 1.0.1 and the pinned capability surface")
    func bootstrapReport() {
        let daemon = DaemonBootstrap(custodian: FakeSecretCustodian(known: []))
        let report = daemon.start()
        #expect(report.version == "1.0.1")
        #expect(report.capabilities == [.availabilityCheck])
        #expect(RuntimeCapability.allCases.allSatisfy {
            !$0.rawValue.lowercased().contains("export")
        })
    }

    @Test("Availability checks return redacted receipts without reference text")
    func availabilityReceipts() async throws {
        let present = try SecretReference(namespace: "test", name: "FAKE_PRESENT")
        let absent = try SecretReference(namespace: "test", name: "FAKE_ABSENT")
        let daemon = DaemonBootstrap(custodian: FakeSecretCustodian(known: [present]))

        let confirmed = await daemon.handle(.availability(present))
        #expect(confirmed.resultClass == .availabilityConfirmed)

        let missing = await daemon.handle(.availability(absent))
        #expect(missing.resultClass == .availabilityAbsent)

        #expect(confirmed.requestDigest.count == 64)
        #expect(!confirmed.requestDigest.contains("FAKE_PRESENT"))
        #expect(confirmed.requestDigest != missing.requestDigest)
    }

    @Test("Custodian failure fails closed with an explicit result class")
    func custodianFailureFailsClosed() async throws {
        let daemon = DaemonBootstrap(custodian: FailingCustodian())
        let reference = try SecretReference(namespace: "test", name: "FAKE_ANY")
        let receipt = await daemon.handle(.availability(reference))
        #expect(receipt.resultClass == .custodianUnavailable)
    }

    @Test("Reference validation rejects empty and malformed parts")
    func referenceValidation() {
        #expect(throws: BrokerContractError.self) {
            try SecretReference(namespace: "", name: "X")
        }
        #expect(throws: BrokerContractError.self) {
            try SecretReference(namespace: "a/b", name: "X")
        }
        #expect(throws: BrokerContractError.self) {
            try SecretReference(namespace: "ok", name: " ")
        }
    }

    @Test("Receipt schema structurally cannot carry secret material")
    func receiptShapeIsRedacted() throws {
        let receipt = BrokeredReceipt(
            requestDigest: String(repeating: "0", count: 64),
            resultClass: .availabilityAbsent
        )
        let data = try JSONEncoder().encode(receipt)
        let object = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(Set(object.keys) == ["requestDigest", "resultClass"])
    }

    @Test("Governance records state ownership, signing, and fake boundaries")
    func governanceRecordsPresent() {
        #expect(PackageGovernance.packageOwnership.contains("Package.swift"))
        #expect(PackageGovernance.packageOwnership.contains("provenance only"))
        #expect(PackageGovernance.releaseSigningPrerequisite.contains("Developer ID"))
        #expect(PackageGovernance.releaseSigningPrerequisite.contains("notarized"))
        #expect(PackageGovernance.fakeFirstBoundary.contains("fakes"))
        #expect(PackageGovernance.fakeFirstBoundary.contains("No production secret access"))
    }
}
