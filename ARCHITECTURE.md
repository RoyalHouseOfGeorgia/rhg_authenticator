# Architecture

## System Overview

The RHG Authenticator is a credential verification system with three principals:

- **Issuer** (the Prince) — Signs credentials with a hardware security key (YubiKey)
- **Holder** (the recipient) — Receives a physical diploma with a QR code
- **Verifier** (anyone) — Scans the QR code to verify authenticity via a public web page

No blockchain, no third-party verification services. Trust is rooted in Ed25519 public key cryptography and a public key registry hosted alongside the verification page.

## Components

The system has two independent components — the TypeScript verifier (1) and the desktop app (2) — plus standalone Python helpers (3–5):

1. **Verification library + page (TypeScript)** — core crypto, credential validation, key registry, and the public-facing verification page on GitHub Pages. This is what the world sees.
2. **Desktop app (native apps over a Go core)** — a SwiftUI app on macOS and a WPF app on Windows, both thin front ends over one Go core library that holds every rule (see [Native apps and the Go core](#native-apps-and-the-go-core)). The core talks directly to the YubiKey via PCSC (`piv-go`), signs credentials and generates QR codes (SVG/PNG). It also signs credentials in bulk from a CSV file (one PIN entry per batch; each row still opens a fresh card session; rows already in the issuance log are skipped). Each platform ships as one file with no external tools: a zipped `.app` with the core linked in, or a single Windows `.exe` that carries the core DLL. On a Mac it updates itself in place (see [App Update Flow](#app-update-flow-macos)). Its Registry tab edits the key registry (keys imported from a YubiKey or a certificate file; entries are never deleted, only given an expiry date) and submits changes as GitHub pull requests via `ghapi` (OAuth Device Flow; see [Design Decisions → Token lifecycle](#design-decisions)). Using the app: [README.md](README.md#using-the-app); the core library: [go/README.md](go/README.md).
3. **URL rebuild tool (Python, `scripts/rebuild_urls.py`)** — standard-library script that rebuilds verification URLs from data already signed (a payload + signature, the desktop app's issuance log, or a CSV). It reproduces the canonical JSON to check each entry but holds no keys and does not verify signatures; the verification page remains the only authenticity check.
4. **QR tool (Python, `scripts/rhg_qr.py`)** — writes an SVG (default) or PNG QR code for a verification URL or payload/signature pair; reuses `rebuild_urls.py` for its checks; needs `segno`.
5. **Revocation hash tool (Python, `scripts/rhg_revocation_hash.py`)** — standard-library script that prints the lowercase SHA-256 of a URL's `p` payload, the value added to `revocations.json`.

## Native apps and the Go core

Diagram: [docs/module-architecture.svg](docs/module-architecture.svg). Go package layout: [go/README.md](go/README.md#package-layout). Where a new feature's code goes: [DEVELOPER.md](DEVELOPER.md#where-feature-logic-goes).

### Layers

- **macOS:** SwiftUI/AppKit views (`macos/Sources/RHGAuthenticator`) → models (`RHGModels`) → bridge (`RHGBridge`) → the C ABI, imported through the `CRHGCore` shim from the cgo-generated `librhgcore.h` (a changed export signature is a compile error). The core is a c-archive linked statically into the app.
- **Windows:** WPF views (`windows/src/RhgAuthenticator.App`) → view models (`RhgAuthenticator.ViewModels`) → bridge (`RhgAuthenticator.Bridge`, P/Invoke) → the C ABI in `rhgcore.dll`, a c-shared library embedded in the `.exe`.
- **Go core:** `go/cmd/rhgcore` (the C exports) → `go/service/rpc` (JSON dispatch, lifecycle, PIN bridge, events; no UI or security logic of its own, no network listener) → `go/service` (the `App`: every feature rule and user-facing text) → the domain packages (`core`, `log`, `yubikey`, `ghapi`, `registry`, `qr`, `bulk`, `errorreport`, `debuglog`, `buildinfo`, `safego`). `go/host` holds the shared start-up steps (data directory, logs, service, update config, command line); `go/update` is the updater.

The arrows are the main path, not a strict rule: the app layer also uses bridge types directly — on macOS the result types; on Windows, `Program.cs` uses the bridge's core-library loader (`CoreLibrary`) and single-instance guard (`SingleInstance`).

The hosts hold no UI-independent rules: they render what the core returns and send what the user does.

### C ABI

Four exports (`go/cmd/rhgcore/exports.go`):

- `char* RHGCall(char* method, char* paramsJSON)` — runs one method. `paramsJSON` is a JSON object (`NULL` or `""` for none). Returns a UTF-8 JSON envelope that the caller frees with `RHGFree`; never `NULL`. It blocks for as long as the method runs (card, network, the PIN prompt, an update install), so a host never calls it on a UI thread.
- `void RHGFree(char* p)` — frees an `RHGCall` result; `NULL` is ignored.
- `void RHGSetEventCallback(rhg_event_cb cb)` with `typedef void (*rhg_event_cb)(const char*)` — every later event goes to `cb` as `{"event":name,"data":payload}`; `NULL` detaches. The string is valid only during the call. The callback may run on any thread, synchronously on the goroutine that emits the event (possibly inside an `RHGCall` on another thread), and must not block: a host copies the string and hands it to its UI thread. An event already being delivered when the callback is replaced may still reach the old one, so a host keeps every callback valid for the life of the process.
- `int RHGMainCLI(int argc, char** argv)` — handles `--version` and `--verify-update-zip` before any UI starts (`argv[0]` is skipped); returns -1 when the UI should start, else the exit code.

The Mac bridge runs `RHGCall` on a concurrent dispatch queue (so `pin.submit` or `app.canQuit` can run while a sign call waits) and feeds events into an unbounded `AsyncStream` (`macos/Sources/RHGBridge/LiveBridge.swift`); the Windows bridge's callback parses the event and writes it to an unbounded channel; nothing in it blocks (`windows/src/RhgAuthenticator.Bridge/LiveBridge.cs`).

The `rhgfake` build (`-tags rhgfake`) of the same library signs with a software card, has no GitHub login, never uses the production registry, reports a version ending in ` (rhgfake)` and adds test-only methods (`go/service/rpc/testhooks_rhgfake.go`). The Swift and .NET test suites run against it (CI jobs: [DEVELOPER.md](DEVELOPER.md#ci-jobs)).

### Messages and lifecycle

A response is either `{"ok":true,"result":…}` (a void method's result is `{}`; empty lists are `[]`, never `null`) or `{"ok":false,"error":{"code","message","offerReport"[,"reportId"]}}`. Params are a single JSON object of at most 1 MiB; unknown fields are rejected. A host branches only on `ok`, the error `code`, `offerReport` and typed result fields; display strings (messages, confirmations, titles) are shown as given and never parsed. The `input` code always means a host bug and `internal` means the call panicked. The method set is `methodTable()` in `go/service/rpc/methods.go`; the parameter, result, error and event shapes are the golden files in `go/service/rpc/testdata/contract/`, which the Swift and .NET contract tests read, so a change on either side fails a test.

A host sets the event callback, calls `app.init` with the data directory (a failure returns to the start, so the host can retry), calls `app.start` once its UI listens, and ends with `app.shutdown`. The methods in `anyStateMethods` (`go/service/rpc/rpc.go`) work in any state; every other method needs a successful `app.init`. Events come from the service (signing and bulk progress, login, registry and history changes) and from `rpc` itself (PIN prompts, update status, internal errors); the full set is in `go/service/rpc/testdata/contract/events/`.

**PIN flow:** when a sign needs a PIN, the service asks its `Prompter`; the `rpc` PIN bridge emits `pin.request` (`requestId`, `rememberDefault`, `maxBytes`), the host shows its native PIN prompt and answers with `pin.submit` or `pin.cancel`. `pin.dismiss` withdraws a prompt (entry timeout, shutdown). One request is pending at a time and each resolves exactly once. Where the PIN lives and how long: [PIN Security](#pin-security).

### Busy and locking rules

The comment on `App` in `go/service/app.go` is the reference. A host never decides by method: it always calls `RHGCall` off its UI thread ([C ABI](#c-abi)). Inside the core, a few `App` methods never block or do only short local work; everything else may block on file, card or network I/O or the PIN prompt. Each family of operations (all card operations share one) has its own busy guard, listed in that comment. A second call while its guard is held fails at once with code `busy` instead of waiting. The `rpc` server's mutex is never held across I/O or an event emit. A running bulk batch, a login and a waiting PIN prompt can be cancelled.

### Panic handling

No panic unwinds into the host. `rpc.Dispatch` recovers a panic in a method, logs the method name, panic type and stack (never the value or params) and returns the `internal` envelope; `go/cmd/rhgcore/call.go` guards the C string conversions around it the same way. `host.OpenLogs` (run by `app.init`) prunes `debug.log` to 30 days, captures the stdlib logger, routes runtime crash output (fatal errors, unrecovered panics) into `debug.log`, and installs the `safego` handler once per process: a goroutine panic goes to stderr and the log, then emits `app.internalError`, which both apps show as a restart alert. Every production goroutine is started with `safego.Go`; a guard test in `go/safego` fails on a bare `go` statement (`go/cmd/rhgcore/main.go` is its walk sentinel). Timer callbacks (`time.AfterFunc` in the PIN cache) are outside it; they only lock and clear memory.

### Windows: core library loading

The `.exe` embeds `rhgcore.dll` with its SHA-256 recorded at build time. At start-up, before anything else, `CoreLibrary` (`windows/src/RhgAuthenticator.Bridge/CoreLibrary.cs`) writes it to `%LOCALAPPDATA%\rhg-authenticator\native\<sha256>\rhgcore.dll` (a file already there with the right hash is kept; the written file is re-hashed) and loads it by full path; the P/Invoke resolver only ever returns that handle. No DLL search path is used, so a `rhgcore.dll` planted beside the `.exe` is never loaded. A failure shows an error box and exits with code 1.

### Windows: single instance

After the command-line invocations (which never start the UI) and before the core starts, `App/Program.cs` opens a per-session (`Local\`) named auto-reset event and then a named mutex (`windows/src/RhgAuthenticator.Bridge/SingleInstance.cs`). The process that created the mutex is the app (a name it cannot open, such as one held by an elevated instance, counts as another instance running); any other launch calls `AllowSetForegroundWindow(ASFW_ANY)`, sets the event and exits 0. The running app restores its window if minimized and brings it, or its open dialog, to the front. The mutex is never owned, so a crashed instance leaves nothing behind.

## Threat Model

- **Trust anchor**: The YubiKey hardware token. Private key never leaves the device.
- **Public registry**: `verify/keys/registry.json` is hosted on GitHub Pages. Integrity is protected by GitHub account access controls and a PR-based review workflow. Changes are submitted as pull requests via the Registry tab, opened from a branch in this repository (operators are Write collaborators; rulesets stop anyone but the maintainer from creating, pushing to or deleting any branch other than the app's `revoke-*` / `registry-update-*` branches and Dependabot's, and from creating or moving any tag); the repository admin reviews and merges. Fetch (including the startup load) reads the registry from `main` via the API when logged in (the Pages copy when logged out, offline, or if the API read fails) and refuses to submit if `main` no longer matches what was loaded, so a stale copy can't silently undo another change.
- **Verification is client-side**: The public verification page fetches the registry and performs all crypto in the browser — no server round-trip.
- **PIN security**: the PIN never leaves the app process — it is never on a command line, in a file or in an event; see [PIN Security](#pin-security).
- **QR as transport**: The QR code is a URL containing the full signed credential. No database lookup required.
- **App updates (macOS)**: the app installs only bundles signed with the pinned release certificate, whose key exists only in the protected `release` GitHub environment that only maintainer-created `v*` tags can use (see [App Update Flow](#app-update-flow-macos)).

### Accepted Risks

- **Distinguishable verification diagnostics (library only)**: `verifyCredential` returns distinct reasons for date- and honor-mismatch, revealing that a valid signature exists for a key whose `to` date or `allowed_honors` excludes the credential. The public page does not display reasons. Accepted — the registry is public anyway.
- **Release signing rests on the maintainer's GitHub account**: whoever controls the maintainer account (tag creation, the `release` environment) can publish a signed update that installs automatically — the same trust the manual download already relied on. A pulled release that a Mac already downloaded may still install; the remedy is a newer patch release.
- **Public key registry is public**: By design. The security property is that only the holder of the YubiKey private key can produce valid signatures.
- **Reported issues never include the error log**: Report Issue (signing-failure) reports are posted to the public tracker without a preview, so they never attach the log; operators send it deliberately via **Export Error Log…** (the Help menu on a Mac, the Help tab on Windows). The error log contains only sanitized internal state (timestamps, error types, stack traces) — no credential data, PINs, or tokens.
- **Release integrity**: only the maintainer can create tags (repository ruleset), release tags must be `vX.Y.Z` (CI refuses others), and published releases are immutable. Collaborators can still create a release by hand on an existing tag, so the app's update check only offers a `vX.Y.Z` release published by the release workflow (`github-actions[bot]`); that filter keeps hand-made releases out of the banner, while the Mac updater's actual security control is the pinned code-signing certificate (see [App Update Flow](#app-update-flow-macos)). Each release carries SLSA build provenance; `gh attestation verify … --signer-workflow …/build.yml --source-ref refs/tags/vX.Y.Z` (README "Binary Integrity") ties a download to that workflow and tag. CI also rejects committed `.syso` object files, since Go links every one in a package into what it builds, the c-shared core DLL included.

## Data Flow

### Issuance Flow

Diagram: [docs/issuance-flow.svg](docs/issuance-flow.svg).

1. Operator opens the app; it downloads the key registry at start-up (if that fails, nothing new is signed until a restart)
2. Operator plugs in the YubiKey
3. Operator fills in credential form (recipient, honor, detail, date)
4. Operator clicks **Sign Credential** → app checks the issuance log for the same payload hash; if found, it skips the PIN prompt and step 5, rebuilds the URL from the logged signature (the same QR as when it was first issued) and adds no log entry. If the issuance log cannot be read, signing is refused; logged records with a malformed signature are ignored. Otherwise it reads the card's public key (no PIN) and refuses, before any PIN prompt, a key that is not in the registry, is not valid on the credential date or may not sign this honor — a credential the verification page would reject. Then it asks for the YubiKey PIN with the native PIN prompt (skipped when a cached PIN is available; see [PIN Security](#pin-security))
5. App opens the YubiKey via PCSC (fresh session per sign), reads the certificate from PIV slot 9c, checks the key again (in case the card was swapped), canonicalizes → signs → verifies round-trip → logs
6. App shows a PNG preview; the SVG (for print) and a 2048px PNG are generated when the operator saves them
7. Operator saves SVG, gives to diploma designer for printing

**Bulk variant:** the operator selects a CSV instead of filling the form. Every row is validated before the PIN prompt (invalid rows are skipped; rows whose payload hash is already in the issuance log are reported as already issued, with the URL rebuilt from the logged signature). The card's key is then read once and checked against every remaining row as in step 4; a refused row fails and the batch goes on without it. The PIN is entered once; each remaining row is then signed and logged as in step 5, minus the QR preview. The batch stops at the first failed row (signing error or failed log write) and marks the remaining rows not attempted, so every signed row is either logged or reported as not logged. Rows duplicating an earlier row of the same file are rejected as invalid. The operator can export a results CSV containing each row's verification URL.

**Duplicate cleanup:** logs written before the duplicate check may hold the same credential more than once. The History tab's **Remove Duplicates…** button keeps the earliest record with a well-formed signature for each payload hash (case-insensitive) and drops later copies; records with a malformed signature before it, or with an empty hash, are kept as-is. It saves a timestamped `.bak-` copy of the log first (a new 0600 file; an existing backup is never overwritten — a clash gets a `-2`, `-3`, … suffix). Log appends and the log rewrites are serialized by a mutex (`writeMu`) in `log/issuance.go`.

**Deleting a record:** the History tab's **Delete Entry…** (`history.deleteEntry`) removes the one exact record from this computer's issuance log, after the same kind of backup. It does not revoke anything: the credential still verifies. Its confirmation (`recordText`'s `deleteConfirm`) warns when no other record of the credential remains, since it can then no longer be revoked from the app, and offers **Revoke Instead** unless the credential is already revoked (`offerRevoke`).

### Verification Flow

Diagram: [docs/verification-flow.svg](docs/verification-flow.svg).

1. Anyone scans QR code on diploma with phone camera
2. Phone opens `https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>`
3. Verification page fetches the key registry and revocation list in parallel (registry failure → error state)
4. Ed25519 signature verified client-side against every registry key; on a match the credential is checked against the revocation list, then the key's `to` date and `allowed_honors`
5. Result displayed: Verified (credential details + authority, with a note if revocation status could not be checked), Credential Revoked, Not Verified, or Verification Error — all with generic text; the specific rejection reason is not shown

### App Update Flow (macOS)

Code: `go/update/` — `manager.go` drives the lifecycle (startup cleanup, checks, download → stage, apply after the UI exits) over check, download, stage, verify, apply, cleanup and eligibility. `app.start` starts the manager; the hosts learn its state from the `update.status` and `update.updated` events and show it in their banners (`macos/Sources/RHGAuthenticator/UpdateBannerView.swift` with `macos/Sources/RHGModels/UpdateBanner.swift`; `windows/src/RhgAuthenticator.ViewModels/UpdateBanner.cs`, which only ever offers **Download**).

1. From `app.start` and every 6 hours (until an update is ready) the app reads GitHub's latest release and considers it only if the tag is `vX.Y.Z`, the author is `github-actions[bot]` and it is newer than the running version
2. **Eligibility:** the bundle must be in `/Applications` or `~/Applications`, not translocated, and writable. Otherwise (or on Windows) the app only shows **Version … is available — Download**, adding a hint to move the app into Applications when it is outside them or translocated
3. **Download:** `rhg-authenticator-darwin-arm64.zip`, which must also have been uploaded by `github-actions[bot]`, capped at 100 MB
4. **Stage:** the zip's central directory is pre-scanned (one top-level `.app` directory, clean relative paths, regular files and directories only — no symlinks — and caps on total size and entry count), extracted into `~/Library/Application Support/rhg-authenticator/update/staged-<ver>/`, then verified: `codesign --verify --deep --strict` against `PinnedRequirement` (`go/update/requirement.go`), sealed `CFBundleShortVersionString` equal to the release tag, and newer than the running version. The banner then reads "Version … is ready to install." with **Restart Now**
5. **Apply:** **Restart Now** goes through the app's normal quit sequence — `app.canQuit` (confirming the discard of unsubmitted registry edits), then `app.shutdown` with `relaunch` set; quitting the app any other way calls `app.shutdown` without it, which applies the update too. `app.shutdown` closes the service, stops the manager and calls `Manager.ApplyIfReady`, which re-verifies the staged bundle, swaps it with the running bundle in one atomic `rename` (`RENAME_SWAP`) and, for Restart Now, relaunches (the old app if the install failed). The next launch shows "Updated to version …" with a **What's New** link. Updates are never forced
6. **Failure:** every failure is logged as an `update: …` line in the error log. A failed download or local staging error is retried at every check; a single failure shows nothing, a repeat (remembered across launches by a `download-failed-<ver>` marker) also shows **Download**. A release that fails the pre-scan or verification, or whose install fails, is marked `apply-failed-<ver>` and from then on offered only as **Download** (never retried automatically). A system tool that timed out or could not run during install is retried at the next quit. A staged update is re-verified at every launch: one that fails re-verification is discarded and downloaded again, and one no longer newer than the installed app is removed

**Trust anchor.** The security control is the pinned code-signing requirement: a self-signed release certificate whose key exists only in the protected `release` GitHub environment, which only `v*` tag runs can use. Tag creation is limited to the maintainer by a repository ruleset, so the ruleset is what keeps the signing key away from other accounts (a tag run uses the workflow from the tagged commit). The sealed-version-equals-tag and newer-than-running checks stop a genuinely signed older bundle from being replayed as a downgrade. The `github-actions[bot]` author/uploader checks are a filter against hand-made releases, not the security boundary. Because every release is signed with the same certificate, macOS keeps the app's Desktop permission across updates, and in-app updates don't need **Open Anyway** because the swapped-in bundle is not quarantined (both confirmed on the first in-app update, v1.5.0 → v1.5.1). Replacing the certificate changes the pin, so every installed app rejects the next update and each user must reinstall manually once (release signing setup: DEVELOPER.md "macOS release signing").

## Credential Revocation

Credentials can be revoked after issuance. The revocation mechanism is hash-based and privacy-preserving.

### Design

- **Revocation list** (`verify/keys/revocations.json`) is hosted on GitHub Pages alongside the key registry.
- **Privacy property**: only opaque SHA-256 hashes of credential payloads are published. No personal data or credential content is exposed.
- **Verification order**: signature is verified first; revocation is checked only after a valid signature is confirmed.
- **Soft failure**: if the revocation list cannot be fetched or fails validation (or `crypto.subtle` is unavailable), verification proceeds and a valid result shows "Revocation status could not be verified." The system does not block valid credentials due to a fetch failure.

### Desktop App

- The **History** tab includes a **Revoke** button with a confirmation. Revoking a credential submits a pull request via the GitHub API (`CreateRevocationPR` in `ghapi`), adding the credential's SHA-256 hash to `revocations.json`. **Delete Entry…** offers **Revoke Instead** (see [Issuance Flow](#issuance-flow)). The logic is in the Go core, shared by both apps ([Native apps and the Go core](#native-apps-and-the-go-core)).
- `core/revocation.go` provides `RevocationEntry`, `RevocationList`, `ValidateRevocationList`, `BuildRevocationSet`, `IsRevoked`, `IsPayloadHash`, and `AppendRevocationEntry` (deep-copies the list and appends a new entry without mutating the input).
- The PR's `revocations.json` is built inside `CreateRevocationPR` from the current file on upstream `main` (Contents API), never from the copy the History tab loaded, so a second revocation can't drop an earlier one. With several revocation PRs open, merge them one at a time; close any PR that conflicts and re-revoke. No PR is opened if the hash is already in that upstream list (`ErrAlreadyRevoked`) or if the user already has an open PR from a `revoke-<hash16>-` branch (`ErrRevocationPending`). If that open-PR check fails, the PR is opened anyway.

### Verification Page (TypeScript)

- `revocation.ts` provides `validateRevocationList`, `buildRevocationSet` and `isRevoked`.
- `verify-page.ts` fetches the revocation list via `fetchRevocationList` (using the shared `fetchAndValidate<T>` helper) and passes a `RevocationCheck` to the verification orchestrator.
- `VerifyPageResult` statuses: `'valid'`, `'revoked'`, `'invalid'`, `'error'`, `'info'` (no parameters).

## TypeScript Modules

Diagram: [docs/module-architecture.svg](docs/module-architecture.svg) (TypeScript section).

| Module | Responsibility | External Deps |
|--------|---------------|---------------|
| `canonical.ts` | Deterministic JSON serialization (key-sort, NFC, no whitespace) | None |
| `base64url.ts` | Base64URL encode/decode, standard Base64 decode | None (uses `btoa`/`atob`) |
| `credential.ts` | Credential v1 schema validation, control char rejection, field length limits, `sanitizeForError` | `validation.ts` |
| `crypto.ts` | Ed25519 sign, verify (`zip215: false`), getPublicKey | `@noble/curves` |
| `registry.ts` | Registry schema validation (incl. `allowed_honors`), key date check (`isDateInRange`, `to`-only), SPKI key decoding | `base64url.ts`, `credential.ts`, `validation.ts` |
| `validation.ts` | Shared date validation (calendar-correct, no `Date` constructor) | None |
| `verify.ts` | Single-pass verification orchestrator | `credential.ts`, `crypto.ts`, `registry.ts`, `revocation.ts` |
| `index.ts` | Public barrel export (verification API: credential, registry, verify, base64url, `crypto.verify`, canonical types) | `base64url.ts`, `canonical.ts` (types), `credential.ts`, `crypto.ts`, `registry.ts`, `verify.ts` |
| `revocation.ts` | Revocation list validation, `buildRevocationSet`, `isRevoked` | `credential.ts`, `validation.ts` |
| `verify-page.ts` | Browser verification page: URL parsing, registry/revocation fetch, DOM rendering | `verify.ts`, `revocation.ts`, `base64url.ts`, `registry.ts` |

## Credential Format

### Schema (v1)

```typescript
type CredentialV1 = {
  date: string;        // ISO 8601 date (YYYY-MM-DD)
  detail: string;      // Specific distinction or rank
  honor: string;       // Title of the honor bestowed
  recipient: string;   // Full name of the recipient
  version: 1;          // Schema version
};
```

All five fields are required. No extra fields allowed. Strings must be non-empty with no leading/trailing whitespace, no control characters (C0/C1/bidi), and within per-field length limits (recipient: 500, honor: 200, detail: 2000, date: 10). Authority is not stored in the credential; it is derived during verification from the registry key whose signature matches.

### Canonical Form

Before signing, the credential is serialized to canonical JSON:

1. Object keys sorted by Unicode code point (equivalent to UTF-8 byte order) at all levels
2. String values NFC-normalized (Unicode normalization); keys are serialized as-is (not normalized)
3. No whitespace between tokens
4. Standard JSON escaping per RFC 8259 §7, as `JSON.stringify` does: `\" \\ \b \f \n \r \t`, other control characters as lowercase `\u00xx`; everything else (including U+2028/U+2029 and non-ASCII) is emitted raw

The canonical bytes are what gets signed and included in the URL (not a re-serialization). Three implementations must agree byte-for-byte — Go (signer), TypeScript (verifier) and Python (`scripts/rebuild_urls.py`) — and all three are tested against `go/testdata/vectors.json`.

### URL Encoding

```
https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>
```

- `p` = Base64URL(canonical JSON bytes)
- `s` = Base64URL(64-byte Ed25519 signature)

Maximum URL length: 625 chars (conservative limit within QR error correction Q capacity). `core.BuildPayload` enforces it (`MaxVerifyURLLength`, via `VerifyURLLength`, which measures the URL `BuildVerifyURL` would produce), so an over-long credential is refused before the PIN prompt in single and bulk signing — never signed and logged without a QR code. The verification page's own `MAX_PAYLOAD_BYTES = 2048` is unchanged.

### QR Code

The Go core generates QR codes as:
- **SVG** (primary) — vector format, scales to any print size without quality loss. The diploma designer imports the SVG and scales to fit.
- **PNG** (preview) — 512px for on-screen display, 2048px for download.

Error correction level Q (25% recovery, `qrcode.High` in the `skip2/go-qrcode` library). Version auto-selected (smallest that fits the URL). Minimum recommended print size: 3×3 cm (encoded in the default SVG filename as `min3cm`).

## Key Registry

### Schema

```typescript
type KeyEntry = {
  authority: string;        // Authority attributed when this key's signature verifies
  from: string;             // Date the key was registered (YYYY-MM-DD) — informational
  to: string | null;        // Last credential date this key verifies (inclusive) or null (no expiration)
  algorithm: 'Ed25519';     // Only Ed25519 supported
  public_key: string;       // Base64: 44-byte SPKI DER or 32-byte raw
  note: string;             // Human-readable description
  allowed_honors?: string[]; // Optional: key verifies only credentials with one of these honors
};

type Registry = { keys: KeyEntry[] };
```

### Verification Rules

- **Dates:** only `to` limits validity. A credential dated after `to` fails; any earlier date verifies, including dates before `from`, so backdated honors work. `from` may be later than `to` (e.g. a key registered with a future `from` and revoked today); the registry is still valid.
- **`allowed_honors`:** a list of exact honor titles (case-sensitive). A credential whose `honor` is not in the list fails. When absent, `null`, `[]` or all-blank, the key verifies any honor; blank items are skipped. Non-string, untrimmed or control-character items reject the registry. The restriction is retroactive — it applies to every credential the key ever signed — and per entry: every entry sharing a public key needs its own `allowed_honors`, or the unrestricted entry verifies.
- **Blank `allowed_honors` fails open (accepted risk):** an edit that blanks a restriction (`[]` or `[""]`) silently makes the key unrestricted instead of rejecting the registry. Accepted because registry edits land only via maintainer-reviewed PRs and the app's Restrictions column shows the effective value.
- **Strict verifier, tolerant app:** the verification page rejects any registry field it does not recognise, so an outdated verifier fails closed instead of silently ignoring a restriction. The desktop app accepts and preserves unknown fields, so new registry fields never break installed copies.

### Key Rotation

Rotate a key by setting the old entry's `to` and adding a new entry; `from` is informational, so ranges need not be disjoint. The old key keeps verifying credentials dated on or before its `to`; the new key verifies any date. Verification tries all registry keys in a single pass, with date-mismatch diagnostics for signatures dated after a key's `to`.

### SPKI DER Format

YubiKey-exported public keys are 44 bytes (12-byte SPKI ASN.1 header + 32-byte raw key). The library's `decodePublicKey` strips the header automatically. Raw 32-byte keys are also accepted.

```
Offset  Length  Content
0       12      SPKI header: 302a300506032b6570032100
12      32      Raw Ed25519 public key
```

## Cryptography

### Algorithm Choice

Ed25519 via `@noble/curves` with `zip215: false` for strict RFC 8032 verification. This rejects non-canonical signatures that some implementations accept.

### Signing (Go core)

YubiKey PIV slot 9c via `go-piv/piv-go` v2 — direct PCSC access, Ed25519 (algorithm 0xE0, requires firmware >= 5.7), through the `crypto.Signer` interface. How the PIN reaches the card: [PIN Security](#pin-security). Signing produces a raw 64-byte signature (R || S). No DER wrapping.

### PIN Security

- PIN is prompted on each single sign and once per bulk batch (default); re-signing an already-logged credential needs no PIN, and a card key that would not verify is refused before any prompt
- **Trust boundary:** the Go core asks for the PIN with the `pin.request` event; the app's native PIN prompt (a sheet on macOS, a dialog on Windows) holds what the operator types as a Swift or C# string, capped to `maxBytes` UTF-8 bytes (the PIV limit, 8; the core caps again), and `pin.submit` passes it in-process across the C ABI to the core, which hands it to `piv-go`. The PIN is never logged, never carried in an event, never on a command line or in a file. The host-side string is not locked or wiped: Swift and .NET strings are managed by their runtimes and may stay in memory until it is reused. An unanswered prompt is withdrawn (`pin.dismiss`) after 5 minutes
- Opt-in caching (**Remember PIN for this session**), in the Go core only: PIN stored in `mlock`'d memory (non-swappable), protected by `sync.Mutex` with generation counter (prevents TOCTOU race on timer expiry), auto-zeroed 5 minutes after the PIN was entered (not extended by use), when caching is unticked, or on app close
- Cached PIN is cleared immediately when the YubiKey rejects it (wrong or blocked PIN), so a mistyped PIN is never silently replayed against the hardware retry counter
- Platform-specific mlock: `syscall.Mlock` on macOS/Linux, `VirtualLock` via `kernel32.dll` on Windows
- YubiKey's built-in 3-attempt PIN retry counter is enforced by the hardware

### Verification (TypeScript)

Verification operates on the original payload bytes, not a re-canonicalized form. This prevents any normalization differences between signing and verification from causing false rejections.

## Security — Core Library

| Defense | Module | Description |
|---------|--------|-------------|
| Prototype pollution | `canonical.ts` | `Object.create(null)` for sorted objects; `__proto__` key rejected |
| Payload size limit | `verify.ts` | `MAX_PAYLOAD_BYTES = 2048` enforced before JSON parsing |
| Log injection | `credential.ts` | `sanitizeForError` strips C0/C1 control characters and bidi overrides |
| Base64 length validation | `base64url.ts` | Rejects remainder-1 inputs (never valid Base64) |
| Control character rejection | `credential.ts` | C0/C1 control characters and bidi overrides rejected in all credential string fields |
| Per-field length limits | `credential.ts` | Compile-time enforced via `satisfies` |
| Extra field rejection | `credential.ts`, `registry.ts` | No unexpected fields pass validation |
| Strict crypto inputs | `crypto.ts` | Length validation on key and signature inputs; type checks on all inputs |
| SPKI prefix verification | `registry.ts` | Byte-by-byte comparison of 12-byte DER header |

## Design Decisions

- **Sync API**: Ed25519 operations are synchronous (`@noble/curves` is pure JS); only the revocation SHA-256 on the verify page uses async Web Crypto.
- **No key_id field**: The registry is too small for O(n) lookup to matter. Signature verification is the real authentication gate.
- **Arithmetic date validation**: Uses manual month/day/leap-year checks instead of `Date` constructor, which silently rolls invalid dates (e.g., Feb 30 → Mar 2).
- **Single-pass verification**: Verify signature against all registry keys; authority is derived from the matching key. Date-mismatch diagnostics reported for valid-but-expired matches.
- **Go for the signing core**: `piv-go` for direct YubiKey access (PIN in-process), `crypto/ed25519` in stdlib. Rust was evaluated but its `yubikey` crate lacks Ed25519 PIV support (issue #602, no progress).
- **Native UIs over a Go core**: a SwiftUI app on macOS and a WPF app on Windows replaced the cross-platform Fyne UI, each over the same Go core built as a C library, so every rule lives once in Go and each app only renders and forwards input ([Native apps and the Go core](#native-apps-and-the-go-core)). CGO is still required: for the C ABI itself, for PCSC on macOS, and MinGW `gcc` to build the c-shared DLL on Windows.
- **SVG as primary QR output**: Vector format scales perfectly for print. No pixel density concerns, no forced QR version needed.
- **Registry fetch**: remote only (10s timeout), no cache or embedded fallback. If the server is unreachable at start-up, the app opens offline: nothing new is signed (the card's key cannot be checked against the registry) until a restart, but an already-issued credential's QR is still rebuilt from the issuance log.
- **Token lifecycle**: OAuth tokens stored in OS keychain (Linux: file fallback with 0600). 90-day local TTL enforced on session restore; expired tokens are cleared and require re-authentication. Tokens validated live against GitHub API on each app startup.
- **Cross-language compatibility**: Go `core/` package produces byte-identical canonical JSON to TypeScript. Verified by test vectors (ASCII, Georgian, NFC edge cases).
- **Build info separation**: Version string lives in `buildinfo.Version` (set via `-ldflags` when `scripts/rhgcore-smoke.sh` builds the core library; CI passes `$GITHUB_REF_NAME` — the tag on a release, otherwise the branch or `<PR>/merge` ref; release checks: [Releasing](DEVELOPER.md#releasing)). `buildinfo.IsDebug()` / `buildinfo.IsRelease()` mark debug builds (the startup log line is tagged "(debug mode)"). The error log (`debug.log`) is always on, captures the stdlib `log` output, and is pruned to 30 days at startup.
- **Panic recovery**: no panic in the core reaches the host; see [Panic handling](#panic-handling). If the `safego` handler itself panics, the default handler logs to stderr and the stdlib log.
- **Auto error reporting**: The `errorreport` package builds sanitized issue bodies (version, OS, error type, the message shown to the user and, for signing errors, the step and hardware error category — never the raw error text or the error log) and files them via the GitHub API if the user is logged in, or falls back to a pre-filled browser URL. Issue titles are prefixed `[Auto]` with labels `bug` + `auto-reported`.
