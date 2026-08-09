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
        .testTarget(
            name: "SecretBrokerBootstrapTests",
            dependencies: [
                "SecretBrokerContracts",
                "SecretBrokerDaemon",
            ]
        ),
    ]
)
