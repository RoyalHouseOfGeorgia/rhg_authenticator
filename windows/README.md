# RHG Authenticator for Windows

The native Windows app: WPF views over the Go core (`rhgcore.dll`, embedded in the exe). How the layers fit together is in [ARCHITECTURE.md](../ARCHITECTURE.md#native-apps-and-the-go-core); CI and releases are in [DEVELOPER.md](../DEVELOPER.md#ci-jobs).

## Layout

```
windows/
├── RhgAuthenticator.sln
├── Directory.Build.props        # Shared settings (warnings as errors, code style); where the core library is found
├── global.json                  # .NET SDK version
├── .editorconfig
├── src/
│   ├── RhgAuthenticator.Bridge/     # The core's C ABI as .NET (net10.0): P/Invoke, loader, RPC methods, params, results, events, single instance
│   ├── RhgAuthenticator.ViewModels/ # View models (net10.0)
│   └── RhgAuthenticator.App/        # The app (net10.0-windows, WPF): views, dialogs, Program.cs, app.ico, app.manifest
└── tests/
    ├── Directory.Build.props        # Tests use the rhgfake core
    ├── RhgAuthenticator.Bridge.Tests/     # Bridge, loader and RPC contract tests
    ├── RhgAuthenticator.ViewModels.Tests/ # View model tests
    └── RhgAuthenticator.FlowRunner/       # Test support: runs one bridge scenario per process
```

## Requirements

- The .NET SDK in `windows/global.json` (later patch versions are accepted)
- PowerShell 7 to build the exe
- Go and a C compiler for the core library — on Windows, Git Bash with MinGW-w64 `gcc` ([go/README.md](../go/README.md#requirements))

## Build and test

Everything runs from the repo root. First build the core library, both variants, into `go/release/rhgcore/{release,rhgfake}/` (see [go/README.md](../go/README.md#building-the-core-library)); on Windows run it in Git Bash with MinGW gcc:

```bash
bash scripts/rhgcore-smoke.sh
```

Then:

```bash
dotnet test windows/RhgAuthenticator.sln
```

The tests load the rhgfake core: `go/release/rhgcore/rhgfake/librhgcore.so` on Linux, `rhgcore.dll` on Windows. Set `RHGCORE_LIB_DIR` to use another directory. On Linux the solution builds with `EnableWindowsTargeting`, set automatically; the App project is built there without the core library and reports the missing library at start-up.

To build the exe (Windows, PowerShell 7), with the release `rhgcore.dll` embedded:

```powershell
pwsh scripts/build-windows-app.ps1 [-Version X.Y.Z] [-LibDir <dir>]
```

The output is `release/windows-app/rhg-authenticator-windows-amd64.exe`. It refuses an rhgfake library and, for any version but `0.0.0`, a library whose `--version` is not `vX.Y.Z`.
