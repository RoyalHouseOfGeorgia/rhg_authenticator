# RHG Authenticator — Desktop Signing App

Self-contained desktop application for signing Royal House of Georgia credentials. Produces QR codes (SVG for print, PNG for preview) that are verified by the public verification page.

## Requirements

- Go 1.25.8+
- YubiKey with Ed25519 key in PIV slot 9c (firmware >= 5.7)

### Platform-Specific

| Platform | PCSC | GUI | Extra Packages |
|----------|------|-----|----------------|
| **macOS** | Built-in (PCSC framework) | Built-in (OpenGL) | None |
| **Windows** | Built-in (WinSCard) | Built-in (OpenGL) | None |

## Build

```bash
make build          # → release/rhg-authenticator
make test           # Run all Go tests
make vet            # Static analysis
make checksums      # Generate SHA256SUMS.txt
make clean          # Remove release directory
```

The binary embeds the version from `git describe --tags`.

## Usage

1. Run `./release/rhg-authenticator` (or `./release/rhg-authenticator --version` to print the version and exit)
2. The app opens immediately with five tabs: **Sign**, **History**, **Registry**, **Audit**, and **YubiKey** (no YubiKey needed yet)

### Sign Tab

1. Fill in the credential form:
   - **Recipient**: full name
   - **Honor**: select from the dropdown (5 recognized titles)
   - **Detail**: specific distinction or rank
   - **Date**: YYYY-MM-DD (defaults to today)
2. Plug in your YubiKey
3. Click **Sign Credential**
4. Enter your YubiKey PIN when prompted
   - Check "Remember PIN for this session" to cache the PIN (opt-in, mlock'd memory, auto-clears after 5 minutes)
5. The QR code appears as a preview
6. Click **Save SVG** (primary — vector for print) or **Save PNG** (2048px alternative)
7. Copy the verification URL to clipboard via **Copy URL**

If signing fails, the status area shows a diagnostic message and a **Report Issue** button (files a GitHub issue automatically if logged in, or opens a pre-filled browser form). In debug builds, details are also written to `debug.log` — see [Troubleshooting](#troubleshooting) below.

### History Tab

Browse previously issued credentials. Search by recipient name. Click any entry for full details. **Revoke** a credential via the Revoke button — this submits a GitHub PR to add the credential's SHA-256 hash to the revocation list.

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

The easiest way is to use the **Registry** tab in the signing app, which can import `.crt`/`.pem` certificate files directly and extract the Ed25519 public key automatically. See [Registry Tab](#registry-tab) below.

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
Then import `cert.crt` via the Registry tab.

## Registry Tab

The **Registry** tab (built into the signing app) manages the key registry:

- **Auto-fetches** the live registry from the server on startup
- **Import from YubiKey** — reads the Ed25519 public key directly from an inserted YubiKey
- **Import certificates** (`.crt`/`.pem`) — extracts Ed25519 public keys from certificate files
- **Add/Edit** registry entries with full validation (entries cannot be deleted — revoke by setting an expiry date)
- **Calendar date pickers** for key validity ranges
- **Submit for Review** — creates a GitHub pull request with the updated registry for admin review
- **GitHub login** via OAuth Device Flow (enter a code in your browser — no technical setup required)
- **Token storage** in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Click any cell** to see the full text in the status bar (long values are truncated with ellipsis in the table)

Workflow:
1. Open the **Registry** tab — it fetches the current production registry automatically
2. Log in to GitHub (one-time — click "Login to GitHub", enter the code shown in your browser)
3. Add/edit entries as needed (entries cannot be deleted — revoke by setting an expiry date)
4. Click **Submit for Review** — a pull request is created automatically
5. The repository admin reviews and merges the PR
6. Deploy (the verification page and signing app both fetch from the hosted registry)

## Key Registry

The app fetches the key registry from `https://verify.royalhouseofgeorgia.ge/keys/registry.json` on startup. **Remote only** — no cache or embedded fallback (a local copy could be tampered with). If the server is unreachable, the app opens in offline mode (signing still works, but YubiKey registry check is unavailable). Restart the app to retry.

## Credential Revocation

The app fetches the revocation list (`revocations.json`) alongside the registry on startup. The revocation list contains only SHA-256 hashes of revoked credential payloads — no personal data.

- **History tab**: the **Revoke** button opens a confirmation dialog, then submits a PR via `ghapi.CreateRevocationPR` adding the credential hash to `revocations.json`.
- **Caching**: `cachedRevocationList` with deep-copy before mutation to prevent races.
- **Soft failure**: if the revocation list fetch fails, the app displays feedback via the `revocationStatus` label in the status bar; verification proceeds without revocation checks.

## Troubleshooting

In **debug builds** (any non-release version, i.e. not a tagged `vX.Y.Z`), the app writes a debug log that is truncated at startup and accumulates entries for the session. On exit, you are prompted to review it. In **release builds**, debug logging is a no-op.

| Platform | Path |
|----------|------|
| **macOS** | `~/Library/Application Support/rhg-authenticator/debug.log` |
| **Windows** | `%APPDATA%\rhg-authenticator\debug.log` |

### Common errors

| Message | Cause | Fix |
|---------|-------|-----|
| **YubiKey not detected** | No YubiKey visible to the smart card service | Unplug and replug the key. Verify CCID is enabled: `ykman config usb` |
| **Smart card service not available** | OS smart card service not running | macOS: built-in, should always work. Windows: ensure the "Smart Card" service is running (`services.msc`) |
| **No signing certificate found on YubiKey (PIV slot 9c)** | Slot 9c has no certificate, or the certificate does not contain an Ed25519 key | Follow [YubiKey Setup](#yubikey-setup) to generate a key and import the certificate. Ed25519 requires firmware >= 5.7 — check with `ykman info` |
| **Signing failed / Failed to read YubiKey** | Catch-all for unexpected errors | Check `debug.log` for the actual error message |

### Verifying YubiKey readiness

1. **Check firmware**: `ykman info` — Ed25519 PIV requires firmware >= 5.7
2. **Check CCID mode**: `ykman config usb` — PIV requires the CCID interface enabled
3. **Check slot 9c**: `ykman piv info` — should show a certificate in slot 9c (SIGNATURE)
4. **Test in-app**: Go to the **YubiKey** tab and click **Check YubiKey** — this reads the key without requiring a PIN

## Security

- **PIN never leaves the process**: `piv-go` talks directly to the YubiKey via PCSC. No subprocess, no command-line arguments, no `/proc` exposure.
- **PIN caching** (opt-in): stored in `mlock`'d memory (non-swappable), protected by mutex, auto-zeroed after 5 minutes of inactivity.
- **Post-sign verification**: every signature is verified immediately after signing to catch hardware errors.
- **Atomic log writes**: issuance records use tmp-file + rename pattern for crash safety.
- **GitHub token in OS keychain**: OAuth tokens are stored via `go-keyring` (macOS Keychain, Windows Credential Manager, Linux Secret Service). File fallback on Linux only (0600 permissions). Token redacted from `fmt.Sprintf` output via `String()`/`GoString()` methods. Tokens expire after 90 days (enforced locally on session restore).
- **Redirect protection**: HTTP client strips `Authorization` header on cross-origin redirects (allows `*.github.com` only).
- **Input sanitization**: All untrusted GitHub API responses are sanitized before logging (control characters replaced, truncated to 500 runes). User-facing error messages are mapped to safe generic text.
- **Panic recovery**: The main goroutine and all spawned goroutines (`safeGo`) catch panics, write a stack trace to `debug.log` and stderr, and show an error dialog instead of silently crashing.
- **Auto error reporting**: Fatal errors and signing failures offer to file a GitHub issue automatically (via `errorreport` package). If the user is logged in, the issue is created via the API; otherwise a pre-filled browser URL is opened. Issue bodies include version, OS, error type, and the last 50 lines of the debug log (sanitized).

## Architecture

```
go/
├── main.go              # App entry point, Fyne window, panic recovery, safeGo, --version
├── buildinfo/           # Build metadata
│   └── buildinfo.go     # Version (set via ldflags), IsRelease/IsDebug helpers
├── core/                # Credential logic (must match TypeScript byte-for-byte)
│   ├── canonical.go     # Deterministic JSON (key-sort, NFC, no whitespace)
│   ├── base64url.go     # Base64URL encode/decode
│   ├── credential.go    # Credential v1 validation
│   ├── date.go          # Calendar-correct date validation
│   ├── format.go        # Date display formatting (YYYY-Mon-DD)
│   ├── hwerror.go       # Hardware error classification (shared by gui + regmgr)
│   ├── rand.go          # Shared RandomHex utility
│   ├── registry.go      # Key registry schema, lookup, fingerprint
│   ├── revocation.go    # RevocationEntry, RevocationList, ValidateRevocationList, BuildRevocationSet, IsRevoked
│   ├── revocation_test.go
│   ├── sanitize.go      # SanitizeForLog + StripControlChars: C0, C1, DEL, bidi (shared by gui + ghapi + debuglog)
│   └── sign.go          # Signing orchestrator
├── debuglog/            # Debug logging (active in non-release builds only)
│   └── debuglog.go      # Append-only timestamped file logger; no-op when path is empty
├── errorreport/         # Auto error reporting
│   └── report.go        # Build issue title/body, file via GitHub API or browser fallback
├── gui/                 # Fyne GUI (signing app)
│   ├── audit_tab.go     # Registry audit (renders commit history from ghapi/commits)
│   ├── history_tab.go   # Issuance log browser, Revoke button (confirmation dialog, PR via ghapi)
│   ├── pindialog.go     # PIN entry dialog (goroutine-safe)
│   ├── sign_tab.go      # Credential form + QR display + Report Issue button
│   ├── signflow.go      # Extracted signing workflow (testable)
│   ├── statusbar.go     # Bottom status bar (key stats, online status, lastUpdateCh coordination, revocationStatus label)
│   └── yubikey_tab.go   # YubiKey registry check (no PIN)
├── ghapi/               # GitHub API client + OAuth device flow
│   ├── keyring.go       # Keyring interface (OS keychain + FakeKeyring for tests)
│   ├── auth.go          # OAuth device flow, token storage, session restore
│   ├── client.go        # GitHub REST API (branches, contents, PRs); safeRedirect, Client.BaseURL for testability, exported DefaultOwner/DefaultRepo/RegistryFilePath
│   ├── commits.go       # FetchRegistryCommits(baseURL, perPage, etag); commitClient with safeRedirect
│   ├── commits_test.go
│   └── issues.go        # CreateIssue (used by errorreport)
├── regmgr/              # Registry Manager (tab in main app)
│   ├── app.go           # Main UI: toolbar, table, login, submit, state management
│   ├── form.go          # Add/Edit entry dialogs (cert import, calendar)
│   ├── certparse.go     # X.509 → Ed25519 key extraction
│   └── fileio.go        # Registry marshal + atomic write
├── yubikey/             # YubiKey hardware adapter
│   ├── adapter.go       # piv-go PIV signing
│   ├── pincache.go      # Secure PIN cache (mlock + mutex + generation counter)
│   ├── mlock_unix.go    # mlock for macOS/Linux
│   └── mlock_windows.go # VirtualLock for Windows
├── qr/                  # QR code generation
│   └── generate.go      # SVG (vector) + PNG output
├── log/                 # Issuance log
│   └── issuance.go      # Atomic append-only JSON log
├── registry/            # Registry fetch
│   └── fetch.go         # Remote-only registry fetch; readLimitedBody helper
├── update/              # Version check
│   └── check.go         # GitHub releases version check
├── testdata/            # Cross-language test vectors + cert fixtures
│   ├── gen_vectors.go   # Vector generator (//go:build ignore)
│   └── vectors.json
├── Makefile
├── go.mod
└── go.sum
```

## Cross-Language Compatibility

The Go `core/` package produces byte-identical output to the TypeScript verification library. This is verified by cross-language test vectors in `testdata/vectors.json` (generated from TypeScript, validated in Go). Credentials signed by the Go app verify correctly on the TypeScript verification page.
