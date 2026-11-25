// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ComputerHistoryKeyStore",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "computer-history-key-store", targets: ["ComputerHistoryKeyStore"])],
    targets: [
        .target(name: "KeyStoreRequest"),
        .executableTarget(name: "ComputerHistoryKeyStore", dependencies: ["KeyStoreRequest"], linkerSettings: [.linkedFramework("Security")]),
        .testTarget(name: "KeyStoreRequestTests", dependencies: ["KeyStoreRequest"])
    ]
)
