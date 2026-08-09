"""PROBE C2, seam widening against the caller-bound dispatch shape.

Supersedes probe-c-plaintext-seam.py for heads at or after ARM-24. That probe
anchored its daemon patch on the public handle(_:), which ARM-24 deleted, so it
now reports INCONCLUSIVE rather than exercising anything. This one anchors on
the private execute(_:) and adapts to either shape.

What it does: widens the custody seam with a plaintext-returning operation, adds
a reveal request case and a value-carrying type, conforms the fakes, and layers
a public value-returning method on the daemon. Every seam and API pin should
fire.

IMPORTANT, and the reason this file is longer than it looks like it needs to be.
Adding a case to BrokeredRequest makes three switches non-exhaustive: the
BrokeredOperationKind initialiser in SecretBrokerCore, and reference(in:) and
execute(_:) in the daemon. If the probe leaves those broken, the package does
not compile, the suite never runs, and the runner records a red that came from
the compiler rather than from any pin. That is a probe caught for the wrong
reason, which proves nothing about the pins. So the probe completes those
switches deliberately, to make the pins the thing under test.

Worth noting in its own right: those compile errors are a real guarantee. A new
request case cannot silently inherit an existing caller grant, because the
operation-kind mapping will not build until someone names it.

Run from the repo root of the clone under test. Every patch is anchored on a
distinctive substring and the script exits non-zero if an anchor is missing,
rather than silently producing a no-op probe that would read as "not caught".
"""
import os
import re
import sys


def patch(path, anchor, replacement, label):
    if not os.path.exists(path):
        sys.exit(f"probe-c2: {path} not found; re-author probe")
    src = open(path).read()
    if anchor not in src:
        sys.exit(f"probe-c2: anchor missing for {label} in {path}; re-author probe")
    open(path, "w").write(src.replace(anchor, replacement, 1))
    print(f"probe-c2 applied: {label}")


CONTRACTS = "Sources/SecretBrokerContracts/BrokeredOperations.swift"

patch(
    CONTRACTS,
    "public protocol SecretCustodian: Sendable {",
    "public protocol SecretCustodian: Sendable {\n"
    "    func plaintextValue(of reference: SecretReference) async throws -> String",
    "plaintext operation on the seam",
)

patch(
    CONTRACTS,
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

# Conform every custodian fake in the adapters target. Done by regex over the
# availability requirement rather than by exact text, because the fakes differ
# from one another and more may be added.
fake_count = 0
for root, _dirs, files in os.walk("Sources/SecretBrokerAdapters"):
    for name in files:
        if not name.endswith(".swift"):
            continue
        path = os.path.join(root, name)
        text = open(path).read()
        if "func availability(of reference: SecretReference)" not in text:
            continue
        patched, hits = re.subn(
            r"(public func availability\(of reference: SecretReference\)"
            r" async throws -> SecretAvailability \{[^}]*\})",
            r'\1\n\n    public func plaintextValue('
            r'of reference: SecretReference) async throws -> String { "fake-plaintext" }',
            text,
        )
        if hits:
            open(path, "w").write(patched)
            fake_count += hits
            print(f"probe-c2 applied: widened {hits} fake(s) in {path}")
if fake_count == 0:
    sys.exit("probe-c2: no custodian fake was widened; re-author probe")

# Complete the operation-kind mapping so the package still builds. Present only
# on the caller-bound shape.
KIND = "Sources/SecretBrokerCore/CallerIdentity.swift"
if os.path.exists(KIND) and "BrokeredOperationKind" in open(KIND).read():
    patch(
        KIND,
        "        case .availability:\n            self = .availability",
        "        case .reveal:\n            self = .availability\n"
        "        case .availability:\n            self = .availability",
        "operation-kind mapping completed so the probe compiles",
    )

DAEMON = "Sources/SecretBrokerDaemon/DaemonBootstrap.swift"
daemon_src = open(DAEMON).read()

# The digest helper was static before ARM-5 correction 1 and an instance method
# after. Probing with the wrong form is a build error, which reads as "caught"
# while testing nothing.
if "static func digest" in daemon_src:
    digest_call = "Self.digest(of: reference)"
elif "func digest" in daemon_src:
    digest_call = "digest(of: reference)"
else:
    sys.exit("probe-c2: digest helper not found; re-author probe")
print(f"probe-c2: digest helper call form detected as {digest_call}")

if "private func reference(in request: BrokeredRequest)" in daemon_src:
    patch(
        DAEMON,
        "        switch request {\n"
        "        case .availability(let reference):\n"
        "            return reference\n"
        "        }",
        "        switch request {\n"
        "        case .availability(let reference):\n"
        "            return reference\n"
        "        case .reveal(let reference):\n"
        "            return reference\n"
        "        }",
        "reference(in:) switch completed",
    )

# The value-returning public method plus the new case in the operation body.
# Anchor on the private execute(_:) where present, falling back to the
# pre-ARM-24 public handle(_:).
if "private func execute(_ request: BrokeredRequest)" in daemon_src:
    anchor = "    private func execute(_ request: BrokeredRequest) async -> BrokeredReceipt {\n        switch request {\n        case .availability(let reference):"
    label = "daemon value-returning method, anchored on execute(_:)"
elif "public func handle(_ request: BrokeredRequest)" in daemon_src:
    anchor = "    public func handle(_ request: BrokeredRequest) async -> BrokeredReceipt {\n        switch request {\n        case .availability(let reference):"
    label = "daemon value-returning method, anchored on handle(_:)"
else:
    sys.exit("probe-c2: no daemon operation body found; re-author probe")

body_head, _, body_tail = anchor.partition("        case .availability(let reference):")
patch(
    DAEMON,
    anchor,
    "    /// Value-returning path layered on top of the widened seam.\n"
    "    public func reveal(_ reference: SecretReference) async -> RevealedSecret? {\n"
    "        guard let value = try? await custodian.plaintextValue(of: reference) else { return nil }\n"
    "        return RevealedSecret(plaintext: value)\n"
    "    }\n\n"
    + body_head
    + "        case .reveal(let reference):\n"
    f"            return BrokeredReceipt(requestDigest: {digest_call}, "
    "resultClass: .availabilityConfirmed)\n"
    "        case .availability(let reference):"
    + body_tail,
    label,
)

print("probe-c2: applied cleanly; the package should build and the pins should fail")
