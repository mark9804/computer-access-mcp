// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HistoryContract",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HistoryContract", targets: ["HistoryContract"]),
        .executable(name: "contract-check", targets: ["contract-check"]),
    ],
    targets: [
        .target(name: "HistoryContract", resources: [.process("Resources")]),
        .executableTarget(name: "contract-check", dependencies: ["HistoryContract"]),
        .testTarget(name: "HistoryContractTests", dependencies: ["HistoryContract"]),
    ]
)
