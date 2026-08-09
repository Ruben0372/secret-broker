"""PROBE C, ARM-5 delta re-verification.

Opens the custody seam: adds a plaintext-returning custodian operation, a
value-carrying Codable type, a reveal request case, and a daemon method that
returns raw material to a caller. At e48db09 this passed all 21 tests
(exit 0). Pass criterion for the corrected head: FAIL.

Run from the repo root of the clone under test. Each patch is anchored on a
distinctive substring; if an anchor is missing the script exits non-zero rather
than silently producing a no-op probe, which would otherwise read as a false
"caught" result.
"""
import sys

def patch(path, anchor, replacement, label):
    src = open(path).read()
    if anchor not in src:
        sys.exit(f"probe-c: anchor missing for {label} in {path}; re-author probe")
    open(path, "w").write(src.replace(anchor, replacement, 1))
    print(f"probe-c applied: {label}")


patch(
    "Sources/SecretBrokerContracts/BrokeredOperations.swift",
    "public protocol SecretCustodian: Sendable {",
    "public protocol SecretCustodian: Sendable {\n"
    "    func plaintextValue(of reference: SecretReference) async throws -> String",
    "plaintext operation on the seam",
)

patch(
    "Sources/SecretBrokerContracts/BrokeredOperations.swift",
    "public enum BrokeredRequest: Sendable, Hashable, Codable {\n"
    "    case availability(SecretReference)\n"
    "}",
    "public enum BrokeredRequest: Sendable, Hashable, Codable {\n"
    "    case availability(SecretReference)\n"
    "    case reveal(SecretReference)\n"
    "}\n\n"
    "/// Caller-facing envelope that carries raw material.\n"
    "public struct RevealedSecret: Sendable, Hashable, Codable {\n"
    "    public let plaintext: String\n"
    "    public init(plaintext: String) { self.plaintext = plaintext }\n"
    "}",
    "reveal case and value-carrying type",
)

FAKES = "Sources/SecretBrokerAdapters/Fakes/InMemorySecretCustodian.swift"
src = open(FAKES).read()
if src.count("public func availability(of reference: SecretReference) async throws -> SecretAvailability {") != 2:
    sys.exit("probe-c: expected two custodian fakes; re-author probe")
src = src.replace(
    "    public func availability(of reference: SecretReference) async throws -> SecretAvailability {\n"
    "        known.contains(reference) ? .present : .absent\n"
    "    }",
    "    public func availability(of reference: SecretReference) async throws -> SecretAvailability {\n"
    "        known.contains(reference) ? .present : .absent\n"
    "    }\n\n"
    "    public func plaintextValue(of reference: SecretReference) async throws -> String {\n"
    '        "fake-plaintext"\n'
    "    }",
    1,
)
src = src.replace(
    "    public func availability(of reference: SecretReference) async throws -> SecretAvailability {\n"
    "        throw ProbeFailure()\n"
    "    }",
    "    public func availability(of reference: SecretReference) async throws -> SecretAvailability {\n"
    "        throw ProbeFailure()\n"
    "    }\n\n"
    "    public func plaintextValue(of reference: SecretReference) async throws -> String {\n"
    "        throw ProbeFailure()\n"
    "    }",
    1,
)
open(FAKES, "w").write(src)
print("probe-c applied: fakes conform to the widened seam")

# The digest helper was a static method at e48db09 and became an instance
# method at 48c0a71. Probing with the wrong form produces a build error, which
# reads as "probe caught" while actually testing nothing. Detect the form.
DAEMON = "Sources/SecretBrokerDaemon/DaemonBootstrap.swift"
daemon_src = open(DAEMON).read()
if "static func digest" in daemon_src:
    digest_call = "Self.digest(of: reference)"
elif "func digest" in daemon_src:
    digest_call = "digest(of: reference)"
else:
    sys.exit("probe-c: digest helper not found in daemon; re-author probe")
print(f"probe-c: digest helper call form detected as {digest_call}")

patch(
    DAEMON,
    "    public func handle(_ request: BrokeredRequest) async -> BrokeredReceipt {\n"
    "        switch request {\n"
    "        case .availability(let reference):",
    "    /// Value-returning path layered on top of the seam.\n"
    "    public func reveal(_ reference: SecretReference) async -> RevealedSecret? {\n"
    "        guard let value = try? await custodian.plaintextValue(of: reference) else { return nil }\n"
    "        return RevealedSecret(plaintext: value)\n"
    "    }\n\n"
    "    public func handle(_ request: BrokeredRequest) async -> BrokeredReceipt {\n"
    "        switch request {\n"
    "        case .reveal(let reference):\n"
    f"            return BrokeredReceipt(requestDigest: {digest_call}, resultClass: .availabilityConfirmed)\n"
    "        case .availability(let reference):",
    "daemon value-returning method and reveal dispatch",
)
