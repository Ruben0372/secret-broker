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
    Enforcement model: the forbidden-token scan over package sources is a \
    best-effort review aid, not a control. It matches text and ordinary Swift \
    can evade it. The controls that hold the boundary are the daemon \
    dependency allowlist, the unexported adapters target, and the seam and API \
    pinning tests that fix the custody protocol method set, the request case \
    list, and the public daemon return types.
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
