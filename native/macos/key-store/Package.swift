// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ComputerAccessKeyStore",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "computer-access-key-store", targets: ["ComputerAccessKeyStore"])],
    targets: [
        .target(name: "KeyStoreRequest"),
        .executableTarget(name: "ComputerAccessKeyStore", dependencies: ["KeyStoreRequest"], linkerSettings: [.linkedFramework("Security")]),
        .testTarget(name: "KeyStoreRequestTests", dependencies: ["KeyStoreRequest"])
    ]
)
