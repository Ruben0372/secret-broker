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
    do not export the adapters target, seam and public API pinning, and an \
    artifact assertion over the compiled daemon module's undefined symbols, \
    which catches a capability regardless of how its source is spelled. The \
    forbidden-token scan over package sources is a best-effort review aid, not \
    a control, because it matches text and ordinary Swift can evade it. \
    Residual limit: the artifact assertion is a denylist of named symbol \
    families, so a capability reached through an already-linked Foundation \
    surface, ProcessInfo environment access being the clearest example, \
    resolves inside Foundation and never appears in the daemon's undefined \
    symbols. These layers raise the cost of an obfuscated capability; they do \
    not make the boundary airtight.
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
