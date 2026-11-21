// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ComputerAccessFixture",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "computer-access-fixture", targets: ["FixtureApp"])],
    targets: [
        .target(name: "VisibleTreeFixtureModel"),
        .executableTarget(name: "FixtureApp", dependencies: ["VisibleTreeFixtureModel"]),
        .testTarget(name: "VisibleTreeFixtureModelTests", dependencies: ["VisibleTreeFixtureModel"]),
    ]
)
