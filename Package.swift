// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "secret-broker",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SecretBrokerContracts", targets: ["SecretBrokerContracts"]),
        .library(name: "SecretBrokerDaemon", targets: ["SecretBrokerDaemon"]),
    ],
    targets: [
        .target(
            name: "SecretBrokerContracts"
        ),
        // The daemon dependency list is pinned by the bootstrap tests; the
        // legacy shell scripts and any export-capable module must never
        // appear here without security review.
        .target(
            name: "SecretBrokerDaemon",
            dependencies: ["SecretBrokerContracts"]
        ),
        // Test doubles for the custody seam. Deliberately not exported as a
        // product and never a daemon dependency, so no adapter can be linked
        // into the runtime. Sources stay under Fakes/; a real adapter needs
        // security review and its own target.
        .target(
            name: "SecretBrokerAdapters",
            dependencies: ["SecretBrokerContracts"]
        ),
        .testTarget(
            name: "SecretBrokerBootstrapTests",
            dependencies: [
                "SecretBrokerContracts",
                "SecretBrokerDaemon",
                "SecretBrokerAdapters",
            ]
        ),
    ]
)
