// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AccessContract",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AccessContract", targets: ["AccessContract"]),
        .executable(name: "contract-check", targets: ["contract-check"]),
    ],
    targets: [
        .target(name: "AccessContract", resources: [.process("Resources")]),
        .executableTarget(name: "contract-check", dependencies: ["AccessContract"]),
        .testTarget(name: "AccessContractTests", dependencies: ["AccessContract"]),
    ]
)
