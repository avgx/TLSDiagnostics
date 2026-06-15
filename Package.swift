// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "TLSDiagnostics",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v15),
        .tvOS(.v15),
        .macOS(.v13),
        .watchOS(.v9),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "TLSDiagnostics",
            targets: ["TLSDiagnostics"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/avgx/SSLPinning.git", from: "1.0.3"),
    ],
    targets: [
        .target(
            name: "TLSDiagnostics",
            dependencies: [
                .product(name: "SSLPinning", package: "SSLPinning"),
            ]
        ),
        .testTarget(
            name: "TLSDiagnosticsTests",
            dependencies: ["TLSDiagnostics"]
        ),
    ]
)
