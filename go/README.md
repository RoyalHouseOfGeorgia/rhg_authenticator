# RHG Authenticator — Go Core

The Go core holds all of the app logic: credential signing and validation, the YubiKey adapter, the issuance log, the key registry and revocation list, GitHub login and pull requests, bulk signing, error reporting and the macOS updater. It is built as a C library (`rhgcore`) that the native apps link: the SwiftUI Mac app ([../macos/](../macos/README.md)) and the WPF Windows app ([../windows/](../windows/README.md)). The apps hold no logic of their own beyond their screens; see [Native apps and the Go core](../ARCHITECTURE.md#native-apps-and-the-go-core) for the layers and the C ABI.

To install a released build instead of building from source, see [Download & install](../README.md#download--install). How to use the app is in [Using the app](../README.md#using-the-app) and [Troubleshooting](../README.md#troubleshooting); release history is in [../CHANGELOG.md](../CHANGELOG.md).

## Requirements

- Go — the version in `go/go.mod`
- A C compiler for cgo: Xcode Command Line Tools on macOS; MinGW-w64 `gcc` with Git Bash on Windows; `gcc` plus `libpcsclite-dev` on Linux (development only — Linux is not a release target)
- For signing: a YubiKey with an Ed25519 key in PIV slot 9c (firmware >= 5.7) — see [YubiKey Setup](#yubikey-setup)

## Tests and checks

Run from `go/` — the main commands CI runs (`.github/workflows/build.yml`, which also runs `go mod verify` and the tests with `-race`):

```bash
go test ./...                     # all tests
go test -tags rhgfake ./buildinfo/... ./service/... ./host/... ./cmd/...   # the rhgfake test build
go vet ./...
go vet -tags rhgfake ./buildinfo/... ./service/... ./host/... ./cmd/...
gofmt -l .                        # must print nothing
go tool govulncheck ./...         # Go version and module advisories
```

The `rhgfake` build tag builds the test variant of the core ([what it changes](../ARCHITECTURE.md#c-abi)). It affects only the packages listed above (`RHGFAKE_PKGS` in `build.yml`). The native apps' tests run against the rhgfake library.

The JSON method contract the native apps test against lives in `service/rpc/testdata/contract/`; how to regenerate it: [Contract golden files](../DEVELOPER.md#contract-golden-files).

## Building the core library

From the repository root:

```bash
bash scripts/rhgcore-smoke.sh
```

The script builds two variants — `release` and `rhgfake` — into `go/release/rhgcore/release/` and `go/release/rhgcore/rhgfake/`, checks that each exports `RHGCall`, `RHGFree`, `RHGSetEventCallback` and `RHGMainCLI`, and runs the C smoke test (`cmd/rhgcore/smoketest/smoke.c`) against each.

| Platform | Build mode | Output |
|----------|------------|--------|
| **macOS** | `c-archive` (built for macOS 14) | `librhgcore.a`, `librhgcore.h`, `librhgcore.link` (the linker flags a host app needs) |
| **Windows** (Git Bash + MinGW `gcc`) | `c-shared` | `rhgcore.dll`, `rhgcore.h`; fails if the DLL imports a MinGW runtime DLL |
| **Linux** | `c-archive` and `c-shared` | as macOS, plus `librhgcore.so` for running the Windows app's .NET tests locally |

- **Version:** `RHGCORE_VERSION` sets the embedded version (default `dev`), passed as `-ldflags "-X …/buildinfo.Version=…"`. How releases set it: [Releasing](../DEVELOPER.md#releasing).
- **Command line:** `--version`, and `--verify-update-zip` used by release CI, run through `RHGMainCLI`, so both built apps answer `--version`.
- **Swift cache:** the script also deletes the Mac app's cached build of each variant ([why](../macos/README.md#build-and-test)).

Building the apps themselves: [../macos/README.md](../macos/README.md) and [../windows/README.md](../windows/README.md). CI also fails on any committed `.syso` file: Go would link it into the Windows DLL.

## Package layout

```
go/
├── cmd/rhgcore/         # The C library: exports.go (RHGCall, RHGFree, RHGSetEventCallback, RHGMainCLI), call.go (C conversions, panic → internal error), cli.go (--version, --verify-update-zip), main.go (unused main; safego guard-test sentinel), smoketest/smoke.c
├── host/host.go         # Start-up shared by every front end: data directory, error log and panic/crash hooks, the service, update manager config, RunCLI
├── service/             # service.App — every feature and all user-facing text
│   ├── app.go           # App, New/Start/Close, busy flags, offline handling
│   ├── sign.go, signkey.go, pin.go     # Sign flow, pre-PIN registry key check, PIN prompt
│   ├── bulk.go          # Bulk sign plan, run, results export
│   ├── history.go       # History, revoke, delete entry, remove duplicates, log export
│   ├── registry.go, certparse.go, fileio.go  # Registry fetch/edit/submit, certificate import, registry JSON
│   ├── auth.go, audit.go, yubikey.go, info.go  # GitHub login, registry audit, YubiKey check, status-bar text
│   ├── messages.go      # Error → user-facing message mapping
│   ├── export.go, export_windows.go, export_other.go  # Checked file saves (Windows: Desktop lookup)
│   ├── fakecard_rhgfake.go  # Software card for the rhgfake build
│   └── rpc/             # JSON method surface over service.App
│       ├── rpc.go       # Dispatch, envelopes, panic recovery
│       ├── methods.go   # methodTable(): every method the apps call
│       ├── events.go, lifecycle.go, pinbridge.go  # Events, app.init/start/shutdown, PIN prompt bridge
│       ├── testhooks.go, testhooks_rhgfake.go     # test.* methods (rhgfake only)
│       └── testdata/contract/  # Golden method/event/error contract shared with the Swift and .NET tests
├── core/                # Credential logic (must match TypeScript byte-for-byte)
│   ├── canonical.go     # Deterministic JSON (key-sort, NFC, no whitespace)
│   ├── base64url.go     # Base64URL encode/decode
│   ├── credential.go    # Credential v1 validation
│   ├── date.go, format.go  # Calendar-correct dates; YYYY-Mon-DD display
│   ├── hwerror.go       # Hardware error classification (used by service)
│   ├── rand.go          # RandomHex
│   ├── redirect.go      # SafeRedirect: HTTPS-only, 10-hop limit
│   ├── registry.go      # Key registry schema, lookup, fingerprint
│   ├── revocation.go    # Revocation list validation, IsRevoked
│   ├── sanitize.go      # SanitizeForLog, StripControlChars
│   └── sign.go          # BuildPayload, HandleSign, BuildVerifyURL (625-character URL limit)
├── bulk/                # CSV input and row checks (input.go); plan, run, results CSV (bulk.go)
├── log/issuance.go      # Atomic JSON issuance log: append, read, dedupe, delete (with backup)
├── registry/fetch.go    # Remote-only registry + revocation list fetch
├── ghapi/               # GitHub: OAuth device flow and keychain token (auth.go, keyring.go), REST client and PRs (client.go), registry commits (commits.go), issues (issues.go)
├── errorreport/report.go  # Report Issue: issue title/body, API or browser fallback
├── qr/generate.go       # QR code SVG + PNG
├── yubikey/             # piv-go adapter, PIN cache (mlock / VirtualLock), Winscard.dll from System32 (winscard_windows.go)
├── debuglog/debuglog.go # Always-on error log (debug.log), 30-day retention
├── safego/safego.go     # Panic-safe goroutines; a guard test bans bare `go` statements
├── buildinfo/           # Version (set via ldflags); FakeBuild (fake.go / release.go); icon_test.go guards icon.png
├── update/              # Release check and macOS in-place updater (see doc.go): check, download, scan/extract/stage, codesign verify against the pinned requirement, swap on quit; *_other.go stubs off macOS
├── packaging/macos/Info.plist  # Mac app bundle template
├── icon.png             # App icon master, 1024×1024 (see DEVELOPER.md "App Icon")
├── testdata/            # Cross-language vectors (gen_vectors.go, vectors.json) + certificate fixtures
├── go.mod
└── go.sum
```

`go/release/` is build output (gitignored).

## YubiKey Setup

### Generate Ed25519 Key (one-time)

```bash
# Generate key in PIV slot 9c
yubico-piv-tool -s 9c -a generate -A ED25519 -o public.pem

# Create self-signed certificate
yubico-piv-tool -s 9c -a verify-pin -a selfsign-certificate \
  -S "/CN=RHG Credential Signing" -i public.pem -o cert.pem

# Import certificate back to YubiKey
yubico-piv-tool -s 9c -a import-certificate -i cert.pem
```

### Export Public Key for Registry

The easiest way is the app's **Registry** tab: in the **Add Entry** form (**Add Entry…** on a Mac), **Import from YubiKey** reads the public key from the inserted key, and **Import Certificate** (**Import Certificate…** on a Mac) extracts it from a `.crt`/`.pem` file. See [Key Registry Format](../DEVELOPER.md#key-registry-format) for the registry workflow.

Alternatively, using command-line tools:

```bash
yubico-piv-tool -a read-certificate -s 9c | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  base64
```

Or using **YubiKey Manager** (`ykman`):
```bash
ykman piv certificates export 9c cert.crt
```
Then import `cert.crt` with **Import Certificate** (**Import Certificate…** on a Mac).

To check a YubiKey is ready, see [Checking a YubiKey](../README.md#checking-a-yubikey).

## Registry, revocation and security

- Key registry and revocation list: [Credential Revocation](../ARCHITECTURE.md#credential-revocation) and [Key Registry Format](../DEVELOPER.md#key-registry-format).
- PIN handling, token storage, panic recovery and the other safeguards: [PIN Security](../ARCHITECTURE.md#pin-security) and the security sections of [../ARCHITECTURE.md](../ARCHITECTURE.md).

## Cross-Language Compatibility

The Go `core/` package produces byte-identical output to the TypeScript verification library. This is verified by cross-language test vectors in `testdata/vectors.json` (generated by `testdata/gen_vectors.go`; the Go, TypeScript and Python tests all check against it). Credentials signed by the Go core verify correctly on the TypeScript verification page.
