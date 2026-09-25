// swift-tools-version: 5.9
//
//  Package.swift
//  NexilisSecurityShield
//
//  The server-configured SecurityShield policy checks, split out of NexilisLite so they can be
//  versioned and shipped on their own. Mirrors NexilisSecurityShield.podspec.
//
//  Order at runtime: NexilisZTA authorizes, SecurityShield.run applies the policy, and only then
//  does NexilisLite open its messaging session (APIS.connect wires the three together).
//
//  Every connection it makes is HTTPS to the policy service; it has no dependency on the
//  nuSDKService socket, and so - unlike NexilisLite - it also builds for the iOS Simulator.
//

import PackageDescription

let package = Package(
    name: "NexilisSecurityShield",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(name: "NexilisSecurityShield", targets: ["NexilisSecurityShield"])
    ],
    dependencies: [
        .package(url: "https://github.com/alqindiirsyam-es/NexilisZTA.git", from: "6.0.7")
    ],
    targets: [
        .target(
            name: "NexilisSecurityShield",
            dependencies: [
                .product(name: "NexilisZTA", package: "NexilisZTA")
            ],
            path: "NexilisSecurityShield/Source"
        )
    ]
)
