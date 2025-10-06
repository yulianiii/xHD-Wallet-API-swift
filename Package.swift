// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "xHD-Wallet-API",
    platforms: [
        .iOS(.v15),
        .watchOS(.v9),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "x-hd-wallet-api",
            targets: ["x-hd-wallet-api"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/a2/MessagePack.swift.git", from: "4.0.0"),
        .package(url: "https://github.com/algorandfoundation/JSONSchema.swift.git", exact: "0.7.0"),
        .package(url: "https://github.com/sinoru/swift-sodium.git", from: "0.0.2"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.1"),
        .package(url: "https://github.com/Electric-Coin-Company/MnemonicSwift.git", from: "2.2.4"),
        .package(url: "https://github.com/realm/SwiftLint", from: "0.55.0"),
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.53.9"),
        .package(url: "https://github.com/norio-nomura/Base32.git", from: "0.9.0"),
    ],
    targets: [
        .target(
            name: "x-hd-wallet-api",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "JSONSchema", package: "JSONSchema.swift"),
                .product(name: "MessagePack", package: "MessagePack.swift"),
                .product(name: "Sodium", package: "swift-sodium"),
            ],
            plugins: [
                .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLint"),
            ]
        ),
        .testTarget(
            name: "x-hd-wallet-apiTests",
            dependencies: ["x-hd-wallet-api",
                           .product(name: "MnemonicSwift", package: "MnemonicSwift"),
                           .product(name: "Base32", package: "Base32")],
            resources: [
                .process("schemas/auth.request.json"),
                .process("schemas/msg.schema.json"),
                .process("schemas/malformed.json"),
            ]
        ),
    ]
)
