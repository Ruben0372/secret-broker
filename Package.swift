// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "secret-broker",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .testTarget(
            name: "SecretBrokerBootstrapTests"
        )
    ]
)
