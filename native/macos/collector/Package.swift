// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ComputerAccessCollector",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CollectorCore", targets: ["CollectorCore"]),
        .executable(name: "computer-access-collector", targets: ["computer-access-collector"]),
    ],
    dependencies: [.package(path: "../contract")],
    targets: [
        .target(name: "CollectorCore", dependencies: [.product(name: "AccessContract", package: "contract")]),
        .target(name: "CCollectorSupport", linkerSettings: [.linkedLibrary("bsm")]),
        .executableTarget(
            name: "computer-access-collector",
            dependencies: [
                "CollectorCore",
                "CCollectorSupport",
                .product(name: "AccessContract", package: "contract"),
            ]
        ),
        .testTarget(name: "CollectorCoreTests", dependencies: ["CollectorCore", .product(name: "AccessContract", package: "contract")]),
        .testTarget(name: "WorkerTransportTests", dependencies: ["computer-access-collector", "CollectorCore"]),
    ]
)
