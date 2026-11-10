# RHG Authenticator for macOS

The native Mac app: SwiftUI views over the Go core (`librhgcore.a`, linked statically). How the layers fit together is in [ARCHITECTURE.md](../ARCHITECTURE.md#native-apps-and-the-go-core); CI and releases are in [DEVELOPER.md](../DEVELOPER.md#ci-jobs).

## Layout

```
macos/
├── Package.swift         # Swift package: targets, macOS minimum, Swift language mode
├── Sources/
│   ├── CRHGCore/         # C module: shim.h includes the core's generated librhgcore.h
│   ├── RHGBridge/        # The core's C ABI as Swift: RPC methods, params, results, events, errors
│   ├── RHGModels/        # View models (Foundation + Observation): AppModel and one model per tab
│   ├── RHGFlowRunner/    # Test support, never shipped: runs one LiveBridge scenario per process
│   └── RHGAuthenticator/ # The app: SwiftUI and AppKit views, menu commands (macOS only)
└── Tests/
    ├── RHGBridgeTests/   # Bridge and RPC contract tests
    └── RHGModelsTests/   # View model tests
```

The bundle's `Info.plist` template is `go/packaging/macos/Info.plist`.

## Requirements

- Xcode — the version CI pins in the "Select Xcode" step of `.github/workflows/build.yml` (the app target needs it; the bridge, models and tests also build with a Swift toolchain on Linux)
- Go and a C compiler for the core library ([go/README.md](../go/README.md#requirements))

## Build and test

Everything runs from the repo root. First build the core library, both variants, into `go/release/rhgcore/{release,rhgfake}/` (see [go/README.md](../go/README.md#building-the-core-library)):

```bash
bash scripts/rhgcore-smoke.sh
```

`RHGBridge`, `RHGModels` and their tests build and run on Linux as well as macOS. The tests need the rhgfake library (a software card and the `test.*` methods):

```bash
RHGCORE_LIB_DIR=$PWD/go/release/rhgcore/rhgfake swift test \
    --package-path macos --scratch-path macos/.build/lib-rhgfake
RHGCORE_LIB_DIR=$PWD/go/release/rhgcore/release swift build -c release \
    --package-path macos --scratch-path macos/.build/lib-release
```

Keep `--scratch-path`: SwiftPM does not relink when only the library changes, so each variant has its own scratch directory, which `rhgcore-smoke.sh` deletes when it rebuilds that variant. A build without it never picks up a rebuilt library.

The app target exists only on macOS. To build the app bundle (ad-hoc signed, zipped to `release/macos-app/rhg-authenticator-darwin-arm64.zip`):

```bash
RHGCORE_LIB_DIR=go/release/rhgcore/release bash scripts/build-macos-app.sh [X.Y.Z]
```

It needs the release library: it refuses an rhgfake build, and for any version but `0.0.0` a library whose `--version` is not `vX.Y.Z`.
