"""PROBE D, ARM-5: evasion of the source-text seam and API pins.

Probe C widened the seam in the obvious way and was caught by six assertions.
Probe D adds the same capability, a caller-reachable path to plaintext, while
staying invisible to the pins' line-prefix parser. Two evasions:

  1. The extra seam method is declared on a sibling protocol that inherits
     SecretCustodian. SeamPinningTests.block() anchors on the literal
     "public protocol SecretCustodian", and "public protocol RevealingCustodian:
     SecretCustodian" does not contain that substring, so the new requirement
     sits outside the scanned block.

  2. The daemon's value-returning entry point is declared "public static func".
     lines(withPrefix:) trims and then matches "public func ", so a declaration
     beginning "public static func" is never collected, and therefore is checked
     by neither the name pin nor the forbidden-return-type pin.

No new request case is added, so that pin is untouched.

Expected at 48c0a71: the suite PASSES, demonstrating the pins constrain the
declaration forms they parse rather than the capability itself.
"""
import sys


def patch(path, anchor, replacement, label):
    src = open(path).read()
    if anchor not in src:
        sys.exit(f"probe-d: anchor missing for {label} in {path}; re-author probe")
    open(path, "w").write(src.replace(anchor, replacement, 1))
    print(f"probe-d applied: {label}")


CONTRACTS = "Sources/SecretBrokerContracts/BrokeredOperations.swift"
src = open(CONTRACTS).read()
if "public protocol SecretCustodian" not in src:
    sys.exit("probe-d: SecretCustodian not found; re-author probe")

# Evasion 1: sibling protocol, outside the anchored block.
src = src.rstrip("\n") + """

/// Sibling seam. Inherits the pinned protocol and adds the value path, so the
/// pinned block never contains this requirement.
public protocol RevealingCustodian: SecretCustodian {
    func plaintextValue(of reference: SecretReference) async throws -> String
}
"""
open(CONTRACTS, "w").write(src)
print("probe-d applied: sibling seam protocol outside the pinned block")

FAKES = "Sources/SecretBrokerAdapters/Fakes/InMemorySecretCustodian.swift"
fakes = open(FAKES).read()
if "InMemorySecretCustodian" not in fakes:
    sys.exit("probe-d: in-memory fake not found; re-author probe")
fakes = fakes.rstrip("\n") + """

/// Fake conforming to the sibling seam.
public struct RevealingFakeCustodian: RevealingCustodian {
    private let known: Set<SecretReference>

    public init(known: Set<SecretReference>) {
        self.known = known
    }

    public func availability(of reference: SecretReference) async throws -> SecretAvailability {
        known.contains(reference) ? .present : .absent
    }

    public func plaintextValue(of reference: SecretReference) async throws -> String {
        "fake-plaintext"
    }
}
"""
open(FAKES, "w").write(fakes)
print("probe-d applied: fake conforming to the sibling seam")

# Evasion 2: value-returning daemon entry point as a static method.
patch(
    "Sources/SecretBrokerDaemon/DaemonBootstrap.swift",
    "    public func start() -> BootstrapReport {",
    "    /// Caller-reachable value path. Declared static so the API pin's\n"
    "    /// line-prefix match for \"public func \" never collects it.\n"
    "    public static func revealMaterial(\n"
    "        from custodian: any RevealingCustodian,\n"
    "        for reference: SecretReference\n"
    "    ) async -> String? {\n"
    "        try? await custodian.plaintextValue(of: reference)\n"
    "    }\n\n"
    "    public func start() -> BootstrapReport {",
    "static value-returning daemon entry point",
)
