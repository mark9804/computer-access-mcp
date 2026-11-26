// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ComputerHistoryMacOS",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "HistoryContract", targets: ["HistoryContract"]),
        .library(name: "CollectorCore", targets: ["CollectorCore"]),
        .library(name: "CollectorRuntime", targets: ["CollectorRuntime"]),
        .executable(name: "contract-check", targets: ["ContractCheck"]),
        .executable(name: "computer-history-collector", targets: ["ComputerHistoryCollector"]),
        .executable(name: "computer-history-key-store", targets: ["ComputerHistoryKeyStore"]),
    ],
    targets: [
        .target(name: "HistoryContract"),
        .executableTarget(
            name: "ContractCheck",
            dependencies: ["HistoryContract"]
        ),
        .target(name: "KeyStoreRequest"),
        .executableTarget(
            name: "ComputerHistoryKeyStore",
            dependencies: ["KeyStoreRequest"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        .target(
            name: "CollectorCore",
            dependencies: ["HistoryContract"]
        ),
        .target(
            name: "CCollectorSupport",
            linkerSettings: [.linkedLibrary("bsm")]
        ),
        .target(
            name: "CollectorRuntime",
            dependencies: ["CollectorCore", "CCollectorSupport", "HistoryContract"]
        ),
        .executableTarget(
            name: "ComputerHistoryCollector",
            dependencies: ["CollectorRuntime"]
        ),
        .testTarget(
            name: "HistoryContractTests",
            dependencies: ["HistoryContract"]
        ),
        .testTarget(
            name: "KeyStoreRequestTests",
            dependencies: ["KeyStoreRequest"]
        ),
        .testTarget(
            name: "CollectorCoreTests",
            dependencies: ["CollectorCore", "HistoryContract"]
        ),
        .testTarget(
            name: "CollectorRuntimeTests",
            dependencies: ["CollectorRuntime", "CollectorCore", "HistoryContract"]
        ),
    ]
)
