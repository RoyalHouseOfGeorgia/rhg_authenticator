# RHG Authenticator — Desktop Signing App

Self-contained desktop application for signing Royal House of Georgia credentials. Produces QR codes (SVG for print or a 2048px PNG; PNG preview in the app) that are verified by the public verification page.

To install a released build instead of building from source, see [Download & install](../README.md#download--install).

## Requirements

- Go 1.27.1+
- YubiKey with Ed25519 key in PIV slot 9c (firmware >= 5.7)

### Platform-Specific

| Platform | PCSC | GUI | Build toolchain |
|----------|------|-----|-----------------|
| **macOS** | Built-in (PCSC framework) | Built-in (OpenGL) | Xcode Command Line Tools (C compiler for cgo) |
| **Windows** | Built-in (WinSCard) | Built-in (OpenGL) | gcc, e.g. MinGW-w64 (C compiler for cgo) |

## Build

```bash
make build          # → release/rhg-authenticator
make test           # Run all Go tests
make vet            # Static analysis
make checksums      # Generate SHA256SUMS.txt
make clean          # Remove release directory
```

The binary embeds the version from `git describe --tags`. Release tags are always `vX.Y.Z` (e.g. `v1.5.0`): CI refuses to build a release from any other tag, and only the maintainer can create tags.

At startup the app checks GitHub for a newer release and shows **Version … available — Download** if there is one. It only considers a release tagged `vX.Y.Z` and published by the release workflow (`github-actions[bot]`), so a release created by hand — even by a collaborator — is never offered.

See [../CHANGELOG.md](../CHANGELOG.md) for release history.

## Usage

1. Run `./release/rhg-authenticator` (or `./release/rhg-authenticator --version` to print the version and exit)
2. The app opens immediately with five tabs: **Sign**, **History**, **Registry**, **Audit**, and **YubiKey** (no YubiKey needed yet)

### Sign Tab

1. Fill in the credential form:
   - **Recipient**: full name
   - **Honor**: select from the dropdown of recognized titles
   - **Detail**: specific distinction or rank
   - **Date**: pick with the 📅 calendar button (defaults to today, UTC; the field itself is read-only)
2. Plug in your YubiKey
3. Click **Sign Credential**
4. Enter your YubiKey PIN when prompted
   - Check "Remember PIN for this session" to cache the PIN (opt-in, mlock'd memory, auto-clears after 5 minutes)
5. The QR code appears as a preview
6. Click **Save SVG** (primary — vector for print) or **Save PNG** (2048px alternative). The save dialog opens on the Desktop; on a Mac, the first save may ask whether the app can access the Desktop — click **Allow**
7. Copy the verification URL to clipboard via **Copy URL**

If the same credential (identical recipient, honor, detail and date) is already in the issuance log, the app skips the PIN prompt, says **"Credential previously generated, no new record created."** and shows the original QR code — nothing new is logged. If the issuance log can't be read, signing is blocked until it can (see [Troubleshooting](#troubleshooting)).

The verification URL must fit a printable QR code (625 characters), which leaves room for roughly 220–290 Latin or 75–95 Georgian letters for recipient and detail combined (the longer the honor title, the less room). A credential that is too long, or otherwise invalid, is refused before the PIN prompt — nothing is signed or logged — and the status area says how much to shorten (e.g. **"Too long to fit in a QR code by about 40 letters (about 14 in Georgian script) — shorten the detail or recipient."**). Bulk Sign marks such rows invalid with the same reason.

If signing fails, the status area shows a diagnostic message and a **Report Issue** button (files a GitHub issue automatically if logged in, or opens a pre-filled browser form). The issue contains the message shown, the signing step and the hardware error category — not the raw error text, which can include local file paths and card-reader names. There is no Report Issue button for an input problem (too long or invalid). Details are written to the error log — see [Troubleshooting](#troubleshooting) below.

### Bulk Sign

Sign many credentials in one session from a CSV file.

1. Prepare a CSV with a header row containing `name`, `honor`, `detail`, `date` (any order, any letter case; extra columns are ignored):
   ```csv
   name,honor,detail,date
   Jane Doe,Order of the Crown of Georgia,Knight Commander,2026-09-24
   ```
   - **honor** must be one of these titles, copied exactly (spelling, punctuation and capitalisation matter):
     - `Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ`
     - `Order of the St. Queen Tamar of Georgia`
     - `Order of the Crown of Georgia`
     - `Medal of Merit of the Royal House of Georgia`
     - `Ennoblement`
     - `Appointment`
     - `Other`

     A row whose honor doesn't match is listed as invalid, and the error lists the allowed titles.
   - **date** must be `YYYY-MM-DD`
   - Limits: 500 rows, 2 MB
2. Plug in your YubiKey and click **Bulk Sign from File…** on the Sign tab
3. Review the confirmation: row counts, the first few names to be signed, and any invalid rows (with line numbers) that will be skipped
4. Click **Sign** and enter your PIN once for the whole batch. If your key requires touch, touch it when it blinks for each row. Expect roughly 0.5–1 s per row
5. When the batch ends, the summary shows how many rows were processed and how many succeeded. Click **Export Results CSV…** to save `name,honor,detail,date,url,status,error` for every row — `url` is the verification URL encoded in the QR code

Each newly signed row is added to the issuance log — click **Refresh** on the History tab to see the new entries. Row statuses in the results file:

| Status | Meaning |
|---|---|
| `signed` | Signed in this run |
| `already_issued` | Already in the issuance log — not signed again; URL rebuilt from the logged signature |
| `invalid` | Skipped: failed validation, or duplicates an earlier row in the same file |
| `failed` | Signing error on this row; the batch stopped here |
| `not_attempted` | The batch was cancelled or stopped before this row |

A wrong PIN, a YubiKey error, or a failure to write the issuance log stops the batch. Rows signed before the stop stay signed and logged; if the stop was a log-write failure, the row that hit it is signed but not logged, and its `error` column says so. **Cancel** stops after the current row. Fix the problem and open the same file again: rows already signed are reported as `already_issued`, so only the remaining rows are signed.

**Excel tips:** use *Save As → CSV UTF-8* (plain "CSV" turns Georgian text into `????`; rows containing `??` are rejected as mis-encoded); format the date column as Text so Excel doesn't rewrite it; keep each cell on one line (no Alt+Enter); if your Excel saves with `;` separators, change the list separator to `,` or the app will reject the file.

### History Tab

Browse previously issued credentials. Search by recipient name. Click any entry for full details. **Revoke** a credential via the Revoke button — this submits a GitHub PR to add the credential's SHA-256 hash to the revocation list.

Revoke needs a working GitHub session and **Write (collaborator) access** to the repository — the PR is opened from a branch in the repository itself, not from a personal fork; without access the app says "ask the maintainer to add you as a collaborator". If you aren't logged in, or GitHub couldn't be reached when the app started, click **Connect to GitHub**. If a revocation fails, the error dialog has an **Export Error Log…** button. If the credential is already revoked, or a revocation PR for it is already open from a branch in the repository (by either operator — open PRs from the old fork-based flow are not detected), no new PR is created and the app says so.

**Remove Duplicates…** finds entries in the issuance log for the same credential signed more than once, and removes all but the earliest valid entry after you confirm (a damaged entry before the first valid copy is left in place). A backup of the current log (`issuances.json.bak-<UTC timestamp>`, e.g. `issuances.json.bak-20261001T120000Z`) is saved next to it first. Removed entries were the same credential, so any QR code already printed from them still verifies.

**Export Issuance Log…** saves a copy of the issuance log. The save dialog opens on the Desktop with a dated name (`rhg-issuances-YYYY-MM-DD.json`); after saving, a message shows exactly where the file went so it can be attached to an email. On a Mac, the first export may ask whether the app can access the Desktop — click **Allow**. If nothing has been signed yet, the button says so instead of opening the dialog.

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

- **Auto-fetches** the registry on startup — from GitHub (`main`) when you're logged in, otherwise from the published site, which can lag `main` by 10–15 minutes after a merge
- **Import from YubiKey** — reads the Ed25519 public key directly from an inserted YubiKey
- **Import certificates** (`.crt`/`.pem`) — extracts Ed25519 public keys from certificate files
- **Add/Edit** registry entries with full validation (entries cannot be deleted — revoke by setting an expiry date; the expiry may be earlier than the informational From date)
- **Calendar date pickers** for key validity ranges
- **Submit for Review** — creates a GitHub pull request with the updated registry for admin review. It's refused if the registry on GitHub changed since you fetched it: click **Fetch from Server**, re-apply your edits, and submit again
- **GitHub login** via OAuth Device Flow (enter a code in your browser — no technical setup required)
- **Token storage** in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Click any cell** to see the full text in the status bar (long values are truncated with ellipsis in the table)

Workflow:
1. Open the **Registry** tab — it fetches the current production registry automatically
2. Log in to GitHub (one-time — click "Login to GitHub", enter the code shown in your browser)
3. Add/edit entries as needed (entries cannot be deleted — revoke by setting an expiry date)
4. Click **Submit for Review** — a pull request is created automatically from a branch in the repository (needs Write collaborator access)
5. The repository admin reviews and merges the PR
6. Deploy (the verification page and signing app both fetch from the hosted registry)

## Key Registry

The app fetches the key registry from `https://verify.royalhouseofgeorgia.ge/keys/registry.json` on startup. **Remote only** — no cache or embedded fallback (a local copy could be tampered with). If the server is unreachable, the app opens in offline mode (signing still works, but YubiKey registry check is unavailable). Restart the app to retry.

The **Registry** tab shows `allowed_honors` (enforced by the verification page) read-only in its **Restrictions** column: "(none)" means unrestricted, "(invalid)" means the verification page would reject the value. Edit it in the registry JSON. Fields the app doesn't recognise are preserved when the tab writes entries back.

## Credential Revocation

The app fetches the revocation list (`revocations.json`) alongside the registry on startup. The revocation list contains only SHA-256 hashes of revoked credential payloads — no personal data.

- **History tab**: the **Revoke** button opens a confirmation dialog, then submits a PR via `ghapi.CreateRevocationPR` adding the credential hash to `revocations.json`.
- **Upstream-built PRs**: `CreateRevocationPR` reads `revocations.json` from upstream `main` and appends to it, so the History tab's loaded copy is only used for display and gating. With several revocation PRs open, merge them one at a time.
- **Soft failure**: if the revocation list fetch fails, the History tab shows **Revocation unavailable** next to its buttons and disables Revoke; click **Refresh** to retry.

## Troubleshooting

The app keeps an error log (`debug.log`) in every build. Entries older than 30 days are removed each time the app starts.

**To send the log:** choose **Help → Export Error Log…** (or click **Export Error Log…** in the Revocation Failed, Remove Duplicates Failed or Submission Failed dialog). The save dialog opens on the Desktop with a dated name (`rhg-error-log-YYYY-MM-DD.log`), ready to attach to an email. The log contains app diagnostics — it may include your GitHub username and file paths, but never PINs or keys.

The file itself lives here:

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
| **Could not read the issuance log, so duplicates can't be checked** | `issuances.json` (next to `debug.log`) is unreadable or no longer valid JSON | Restore it from the newest `issuances.json.bak-*` next to it or from an exported copy, then sign again. **Help → Export Error Log…** shows the exact error |
| **Too long to fit in a QR code by about N letters …** | Recipient + detail don't fit a printable QR code (roughly 220–290 Latin or 75–95 Georgian letters combined) | Shorten the Detail (or Recipient) by at least the amount shown. Nothing was signed or logged |
| **Invalid credential data: …** | A field breaks a rule (e.g. detail over 2000 characters, invalid date, control characters) | Fix the field named in the message and sign again |
| **Your GitHub account can't submit changes to this repository** | The logged-in GitHub account isn't a collaborator with Write access | Ask the maintainer to add you as a collaborator and accept the e-mailed invitation, then try again |
| **Signing failed / Failed to read YubiKey** | Catch-all for unexpected errors | **Help → Export Error Log…** and send the file |
| **Offline — Reconnect** (Registry tab) / Revoke stays disabled | GitHub couldn't be reached when the app started | Click **Offline — Reconnect** (or **Connect to GitHub** on the History tab). If it still can't connect, check your network and try again |
| **Could not save the SVG file / PNG file / issuance log / error log** | macOS: the app was denied access to the folder (usually the Desktop) | System Settings → Privacy & Security → Files and Folders → RHG Authenticator → turn on **Desktop**. May be needed again after installing a new version |

### Verifying YubiKey readiness

1. **Check firmware**: `ykman info` — Ed25519 PIV requires firmware >= 5.7
2. **Check CCID mode**: `ykman config usb` — PIV requires the CCID interface enabled
3. **Check slot 9c**: `ykman piv info` — should show a certificate in slot 9c (SIGNATURE)
4. **Test in-app**: Go to the **YubiKey** tab and click **Check YubiKey** — this reads the key without requiring a PIN

## Security

- **PIN never leaves the process**: `piv-go` talks directly to the YubiKey via PCSC. No subprocess, no command-line arguments, no `/proc` exposure.
- **PIN caching** (opt-in): stored in `mlock`'d memory (non-swappable), protected by mutex, auto-zeroed 5 minutes after the PIN is entered.
- **Post-sign verification**: every signature is verified immediately after signing to catch hardware errors.
- **Atomic log writes**: issuance records use tmp-file + rename pattern for crash safety. Appends and **Remove Duplicates** are serialized, so neither can drop the other's records; Remove Duplicates saves a `.bak-` copy of the log first.
- **GitHub token in OS keychain**: OAuth tokens are stored via `go-keyring` (macOS Keychain, Windows Credential Manager, Linux Secret Service). File fallback on Linux only (0600 permissions). Token redacted from `fmt.Sprintf` output via `String()`/`GoString()` methods. Tokens expire after 90 days (enforced locally on session restore).
- **Redirect protection**: HTTP client strips `Authorization` header on cross-origin redirects (allows `*.github.com` only).
- **Input sanitization**: All untrusted GitHub API responses are sanitized before logging (control characters replaced, truncated to 500 runes). User-facing error messages are mapped to safe generic text.
- **Panic recovery**: a main-goroutine panic writes a stack trace to the error log (`debug.log`) and stderr before exiting. Every goroutine started with a `go` statement is started via `safego.Go`, which recovers a panic, logs it to stderr and the error log, and shows an error dialog instead of crashing. A guard test (`safego/safego_test.go`) fails on any bare `go` statement in production code. (Timer callbacks such as the PIN cache's `time.AfterFunc` are not covered; they only lock and clear memory.)
- **Error reporting** (`errorreport` package): signing failures offer a **Report Issue** button. If the user is logged in, the issue is created via the API; otherwise a pre-filled browser URL is opened. Issue bodies include version, OS, error type, the message shown to the user and, for signing errors, the signing step and hardware error category — never the raw error text or the error log, because they are posted without a preview. Send the log deliberately with **Help → Export Error Log…**. Fatal startup errors show a dialog with the issues link; they are not filed automatically.

## Architecture

```
go/
├── main.go              # App entry point, Fyne window, Help menu, panic recovery, panic handler, --version
├── icon.png             # App icon, 1024×1024 (embedded; also the macOS .icns and Windows .exe icon — see DEVELOPER.md "App Icon")
├── packaging/macos/Info.plist # macOS app bundle metadata
├── buildinfo/           # Build metadata
│   └── buildinfo.go     # Version (set via ldflags), IsRelease/IsDebug helpers
├── bulk/                # Bulk signing: CSV input, row planning, sign loop, results CSV
│   ├── input.go         # ReadInput (2 MB cap, UTF-8/BOM) + ParseCSV (header mapping, row checks)
│   └── bulk.go          # Plan (validate, dedup vs log + file), Run, WriteResultCSV, Summarize
├── core/                # Credential logic (must match TypeScript byte-for-byte)
│   ├── canonical.go     # Deterministic JSON (key-sort, NFC, no whitespace)
│   ├── base64url.go     # Base64URL encode/decode
│   ├── credential.go    # Credential v1 validation
│   ├── date.go          # Calendar-correct date validation
│   ├── format.go        # Date display formatting (YYYY-Mon-DD)
│   ├── hwerror.go       # Hardware error classification (shared by gui + regmgr)
│   ├── rand.go          # Shared RandomHex utility
│   ├── redirect.go      # SafeRedirect: HTTPS-only, 10-hop limit for unauthenticated clients
│   ├── registry.go      # Key registry schema, lookup, fingerprint
│   ├── revocation.go    # RevocationEntry, RevocationList, ValidateRevocationList, BuildRevocationSet, IsRevoked
│   ├── sanitize.go      # SanitizeForLog + StripControlChars (C0, C1, DEL, bidi; 500-rune log cap) + TrimJS; used across packages
│   └── sign.go          # Signing orchestrator (BuildPayload, HandleSign, BuildVerifyURL)
├── debuglog/            # Always-on error log (debug.log), 30-day retention
│   └── debuglog.go      # Append-only timestamped file logger, Prune, stdlib log capture
├── errorreport/         # Auto error reporting
│   └── report.go        # Build issue title/body, file via GitHub API or browser fallback
├── gui/                 # Fyne GUI (signing app)
│   ├── audit_tab.go     # Registry audit (renders commit history from ghapi/commits)
│   ├── bulk_flow.go     # Bulk sign orchestration (Fyne-free): load plan, PIN once, run
│   ├── bulk_sign.go     # Bulk sign dialogs: file pick, confirm, progress, summary + export
│   ├── history_tab.go   # Issuance log browser, Revoke button (confirmation dialog, PR via ghapi; skips already-revoked/pending), Export Issuance Log, Remove Duplicates, Revocation unavailable status
│   ├── errorlog_export.go # Help → Export Error Log… save flow; ShowErrorWithLogExport error dialog
│   ├── pindialog.go     # PIN entry dialog (goroutine-safe)
│   ├── sign_tab.go      # Credential form + QR display + Report Issue button
│   ├── signflow.go      # Extracted signing workflow incl. duplicate-issuance check (testable)
│   ├── statusbar.go     # Bottom status bar (key stats, online status, last registry update via lastUpdateCh)
│   └── yubikey_tab.go   # YubiKey registry check (no PIN)
├── ghapi/               # GitHub API client + OAuth device flow
│   ├── keyring.go       # Keyring interface (OS keychain + FakeKeyring for tests)
│   ├── auth.go          # OAuth device flow, token storage, session restore
│   ├── client.go        # GitHub REST API (branches, contents, same-repository PRs incl. CreateRegistryPR/CreateRevocationPR); safeCheckRedirect (auth stripping), Client.BaseURL for testability, exported DefaultOwner/DefaultRepo/RegistryFilePath; UserMessage (safe user-facing error text)
│   ├── commits.go       # FetchRegistryCommits(baseURL, perPage, etag); commitClient with core.SafeRedirect
│   └── issues.go        # CreateIssue (used by errorreport)
├── regmgr/              # Registry Manager (tab in main app)
│   ├── app.go           # Main UI: toolbar, table, login, submit, state management
│   ├── form.go          # Add/Edit entry dialogs (cert import, calendar)
│   ├── certparse.go     # X.509 → Ed25519 key extraction
│   └── fileio.go        # MarshalRegistry: indented JSON + re-validation
├── yubikey/             # YubiKey hardware adapter
│   ├── adapter.go       # piv-go PIV signing
│   ├── pincache.go      # Secure PIN cache (mlock + mutex + generation counter)
│   ├── mlock_unix.go    # mlock for macOS/Linux
│   └── mlock_windows.go # VirtualLock for Windows
├── qr/                  # QR code generation
│   └── generate.go      # SVG (vector) + PNG output
├── log/                 # Issuance log
│   └── issuance.go      # Atomic JSON issuance log: append, read, dedupe (with backup)
├── registry/            # Registry fetch
│   └── fetch.go         # Remote-only registry + revocation list fetch, key/authority lookup; readLimitedBody helper
├── safego/              # Panic-safe goroutines
│   └── safego.go        # Go (recover + handler), SetPanicHandler; guard test bans bare `go`
├── update/              # Version check
│   └── check.go         # Latest-release check: only vX.Y.Z tags published by github-actions[bot]
├── testdata/            # Cross-language test vectors + cert fixtures
│   ├── gen_vectors.go   # Vector generator (//go:build ignore)
│   ├── vectors.json
│   └── test-ed25519.crt, test-rsa.crt  # cert fixtures
├── Makefile
├── go.mod
└── go.sum
```

## Cross-Language Compatibility

The Go `core/` package produces byte-identical output to the TypeScript verification library. This is verified by cross-language test vectors in `testdata/vectors.json` (generated by `testdata/gen_vectors.go`; the Go, TypeScript and Python tests all check against it). Credentials signed by the Go app verify correctly on the TypeScript verification page.
