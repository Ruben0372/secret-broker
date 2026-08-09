/// Governance record for the v1.0.1 foundations. It lives in source because
/// the repository operating guide is a generated file that must not be hand
/// edited; the bootstrap tests assert these records stay present and stated.
public enum PackageGovernance {
    public static let packageOwnership = """
    Package ownership: Ruben0372/secret-broker, Armel Secret Broker v1.0.1 \
    foundations. ARM-5 / W0-005 owns Package.swift, \
    Sources/SecretBrokerDaemon, Sources/SecretBrokerContracts, \
    Sources/SecretBrokerAdapters, Tests/SecretBrokerBootstrapTests, and \
    .github/workflows. Real custody (Keychain), Signal transport, and core \
    orchestration modules belong to later issues under separate ownership; \
    the legacy shell scripts are provenance only and are owned by history, \
    not by any runtime target.
    """

    public static let enforcementModel = """
    Enforcement model, layered: the daemon dependency allowlist, products that \
    do not export the adapters target, seam and public API pinning, and \
    artifact assertions over the compiled modules' undefined symbols. The \
    artifact layer is two checks: a reviewed golden allowlist per module that \
    notices anything new, and a denylist that names known-bad families with a \
    readable failure. The forbidden-token scan over package sources is a \
    best-effort review aid, not a control, because it matches text and \
    ordinary Swift can evade it.

    Golden files: symbol sets are only comparable within one compiler \
    identity, so each golden is keyed by the Swift version and target triple \
    that produced it. A build under an identity with no committed golden fails \
    loudly as an unreviewed toolchain and never falls back to another \
    identity's file. Regenerating or adding a golden is a reviewed act \
    performed under the matching toolchain and reviewed symbol by symbol, \
    never a casual refresh, because a blind regeneration adopts whatever \
    capability was just introduced and reports success. Failures are reported \
    in three distinct classes, new capability symbol, toolchain drift in \
    runtime or autolink classes, and unreviewed toolchain identity, so the \
    control cannot decay into noise that gets refreshed away.

    Honest limits: the artifact check is macOS and Objective-C interop \
    specific. The stable signal is the _OBJC_CLASS_$_ class reference; \
    selector stubs are not the primary signal and are not relied on. The \
    residual limit is capability reachable through APIs a module already \
    legitimately links, which by definition introduces no new symbol. These \
    layers raise the cost of an obfuscated capability and narrow what can be \
    added unnoticed; they do not make the boundary airtight.
    """

    public static let receiptCorrelationBoundary = """
    Receipt correlation: receipt digests are keyed with a process-wide key that \
    the runtime generates at first access and holds in memory only. Receipts \
    therefore correlate for the lifetime of a daemon process, including across \
    separate daemon instances inside that process, and are unlinkable across \
    restarts by design. A restart is deliberately a clean break: nothing \
    persists that would tie new receipts to old ones.
    """

    public static let callerVerificationGate = """
    Caller verification gate: every daemon entry point is caller bound. There \
    is no unverified public path, so a request cannot reach an operation \
    without an identity to check. Production verification is disabled until a \
    release signing identity exists, because deciding that an audit token \
    belongs to a trusted caller requires one, and while it is disabled the \
    production verifier denies every call including well-formed ones. The \
    boundary is therefore closed by default and opening it is a deliberate act \
    that must arrive with the identity. Do not substitute a weaker check to \
    unblock work: an approximate caller check is worse than a closed door, \
    because it looks like a boundary. Denials name the dimension that failed, \
    bundle, team, user, operation, debug identity, missing audit token, or \
    designated requirement, so a widened check cannot hide behind an unchanged \
    refusal.
    """

    public static let releaseSigningPrerequisite = """
    Release signing prerequisite: daemon binaries must be signed with a \
    Developer ID identity and notarized before any release artifact or \
    LaunchAgent installation exists. No release tag is cut from this package \
    until a signing identity is provisioned. Local and CI builds run \
    unsigned and are development evidence only.
    """

    public static let fakeFirstBoundary = """
    Fake-first boundary: every test in this package runs against fakes and \
    disposable state only. No production secret access, no Keychain \
    namespace access, no real credentials, no environment export. Custody \
    doubles live in SecretBrokerAdapters under Fakes/, which is not exported \
    as a product and is never a daemon dependency, so no adapter can be \
    linked into the runtime. Real custody arrives in a dedicated module with \
    a dedicated test Keychain namespace in a later issue.
    """
}
