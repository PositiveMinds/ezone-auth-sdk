// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EzoneSDK",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .watchOS(.v8),
        .tvOS(.v15),
    ],
    products: [
        .library(name: "EzoneSDK", targets: ["EzoneSDK"]),
    ],
    targets: [
        .target(name: "EzoneSDK", path: "Sources/EzoneSDK"),
        .testTarget(name: "EzoneSDKTests", dependencies: ["EzoneSDK"], path: "Tests/EzoneSDKTests"),
    ]
)
