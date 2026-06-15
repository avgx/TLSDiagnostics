// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "TLSDiagnostics",
    products: [
        .library(
            name: "TLSDiagnostics",
            targets: ["TLSDiagnostics"]
        ),
    ],
    targets: [
        .target(
            name: "TLSDiagnostics"
        ),
        .testTarget(
            name: "TLSDiagnosticsTests",
            dependencies: ["TLSDiagnostics"]
        ),
    ]
)
