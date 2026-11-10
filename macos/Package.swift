// swift-tools-version: 6.2
//
// The native macOS app's Swift package. RHGBridge talks to the Go core
// (librhgcore.a, a Go c-archive) through its C ABI; it and its tests build and
// run on Linux too.
//
// The library comes from RHGCORE_LIB_DIR (default: ../go/release/rhgcore/rhgfake,
// the test build). SwiftPM does not relink when only the archive or the env
// var changes, so each variant gets its own --scratch-path (macos/.build/lib-<variant>,
// clear of SwiftPM's own names), and scripts/rhgcore-smoke.sh deletes a
// variant's scratch path when it rebuilds that variant's library. A build
// without --scratch-path (macos/.build) never picks up a rebuilt library.
// Local loop, from the repo root:
//
//   bash scripts/rhgcore-smoke.sh    # builds both variants into go/release/rhgcore/{release,rhgfake}
//   RHGCORE_LIB_DIR=$PWD/go/release/rhgcore/rhgfake swift test \
//       --package-path macos --scratch-path macos/.build/lib-rhgfake
//   RHGCORE_LIB_DIR=$PWD/go/release/rhgcore/release swift build -c release \
//       --package-path macos --scratch-path macos/.build/lib-release
//
// Tests need the rhgfake variant (RHGFlowRunner uses its test.* methods).

import PackageDescription

let packageDir = Context.packageDirectory
let repoRoot = String(packageDir[..<(packageDir.lastIndex(of: "/") ?? packageDir.startIndex)])
let libDir = Context.environment["RHGCORE_LIB_DIR"] ?? repoRoot + "/go/release/rhgcore/rhgfake"

// The header search path for CRHGCore's shim.h, which includes the library's
// generated librhgcore.h (system library targets take no settings). Every
// Swift target that links RHGBridge needs it too: although RHGBridge imports
// CRHGCore `internal`, release builds (cross-module optimization) load the C
// module when compiling its clients.
let coreHeaderSettings: [SwiftSetting] = [.unsafeFlags(["-Xcc", "-I", "-Xcc", libDir])]

let package = Package(
    name: "rhg-authenticator-macos",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "RHGBridge", targets: ["RHGBridge"]),
        .library(name: "RHGModels", targets: ["RHGModels"]),
    ],
    targets: [
        .systemLibrary(name: "CRHGCore", path: "Sources/CRHGCore"),
        .target(
            name: "RHGBridge",
            dependencies: ["CRHGCore"],
            swiftSettings: coreHeaderSettings,
            // A copy of librhgcore.link (scripts/rhgcore-smoke.sh link_flags) per
            // platform, which a manifest cannot read: keep the two in sync. Linux
            // names the archive (-l:librhgcore.a): librhgcore.so sits beside it,
            // and -lrhgcore would pick that.
            linkerSettings: [
                .unsafeFlags(["-L", libDir]),
                .linkedLibrary("rhgcore", .when(platforms: [.macOS])),
                .unsafeFlags(["-l:librhgcore.a"], .when(platforms: [.linux])),
                .linkedLibrary("pcsclite", .when(platforms: [.linux])),
                .linkedLibrary("pthread", .when(platforms: [.linux])),
                .linkedLibrary("resolv", .when(platforms: [.linux])),
                .linkedFramework("PCSC", .when(platforms: [.macOS])),
                .linkedFramework("CoreFoundation", .when(platforms: [.macOS])),
                .linkedFramework("Security", .when(platforms: [.macOS])),
            ]
        ),
        // The view models: Foundation + Observation only, built and tested on
        // Linux. The SwiftUI views bind to them.
        .target(
            name: "RHGModels", dependencies: ["RHGBridge"],
            // Unoptimized in release too: Xcode 26.6's swift-frontend crashes
            // optimizing this module (LLVM verifier, "Instruction does not
            // dominate all uses" in AppModel.swift.o); debug builds are fine.
            // View models gain nothing from -O. Retry without it when the
            // Xcode pin in build.yml moves.
            swiftSettings: coreHeaderSettings + [.unsafeFlags(["-Onone"], .when(configuration: .release))]),
        // Test support, never shipped: runs one LiveBridge scenario per process.
        .executableTarget(name: "RHGFlowRunner", dependencies: ["RHGBridge"], swiftSettings: coreHeaderSettings),
        .testTarget(
            name: "RHGBridgeTests", dependencies: ["RHGBridge", "RHGFlowRunner"], swiftSettings: coreHeaderSettings),
        .testTarget(name: "RHGModelsTests", dependencies: ["RHGModels"], swiftSettings: coreHeaderSettings),
    ],
    swiftLanguageModes: [.v6]
)

// The app itself (SwiftUI and AppKit), macOS only; its binary is
// rhg-authenticator, the bundle's CFBundleExecutable
// (scripts/build-macos-app.sh assembles the .app).
#if os(macOS)
package.products.append(.executable(name: "rhg-authenticator", targets: ["RHGAuthenticator"]))
package.targets.append(
    .executableTarget(
        name: "RHGAuthenticator", dependencies: ["RHGModels", "RHGBridge"], swiftSettings: coreHeaderSettings))
#endif
