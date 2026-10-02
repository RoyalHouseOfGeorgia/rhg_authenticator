# Architecture

## System Overview

The RHG Authenticator is a credential verification system with three principals:

- **Issuer** (the Prince) — Signs credentials with a hardware security key (YubiKey)
- **Holder** (the recipient) — Receives a physical diploma with a QR code
- **Verifier** (anyone) — Scans the QR code to verify authenticity via a public web page

No blockchain, no third-party verification services. Trust is rooted in Ed25519 public key cryptography and a public key registry hosted alongside the verification page.

## Components

The system has two independent components — the TypeScript verifier (1) and the Go app (2, with its registry manager tab, 3) — plus standalone Python helpers (4–6):

1. **Verification library + page (TypeScript)** — core crypto, credential validation, key registry, and the public-facing verification page on GitHub Pages. This is what the world sees.
2. **Signing app (Go)** — self-contained desktop application with Fyne GUI. Talks directly to YubiKey via PCSC (`piv-go`), signs credentials, generates QR codes (SVG/PNG). Also signs credentials in bulk from a CSV file (one PIN entry per batch; each row still opens a fresh card session; rows already in the issuance log are skipped). Single binary, no external tools required. See [go/README.md](go/README.md) for details.
3. **Registry manager (Go, tab in signing app)** — integrated tab for managing the key registry. Imports Ed25519 public keys directly from an inserted YubiKey or from `.crt`/`.pem` certificate files, supports add/edit of registry entries with date pickers (entries cannot be deleted — revoke by setting an expiry date), fetches the live registry from the server. Changes are submitted as GitHub pull requests for admin review via the `ghapi` package (OAuth Device Flow, token stored in OS keychain with 90-day local TTL). Table cells show truncated text with ellipsis; click any cell to see the full value in the status bar.
4. **URL rebuild tool (Python, `scripts/rebuild_urls.py`)** — standard-library script that rebuilds verification URLs from data already signed (a payload + signature, the signing app's issuance log, or a CSV). It reproduces the canonical JSON to check each entry but holds no keys and does not verify signatures; the verification page remains the only authenticity check.
5. **QR tool (Python, `scripts/rhg_qr.py`)** — writes an SVG (default) or PNG QR code for a verification URL or payload/signature pair; reuses `rebuild_urls.py` for its checks; needs `segno`.
6. **Revocation hash tool (Python, `scripts/rhg_revocation_hash.py`)** — standard-library script that prints the lowercase SHA-256 of a URL's `p` payload, the value added to `revocations.json`.

## Threat Model

- **Trust anchor**: The YubiKey hardware token. Private key never leaves the device.
- **Public registry**: `verify/keys/registry.json` is hosted on GitHub Pages. Integrity is protected by GitHub account access controls and a PR-based review workflow. Changes are submitted as pull requests via the Registry tab, opened from a branch in this repository (operators are Write collaborators; rulesets stop anyone but the maintainer from updating `main` or creating `v*` tags); the repository admin reviews and merges. Fetch (including the startup load) reads the registry from `main` via the API when logged in (the Pages copy when logged out, offline, or if the API read fails) and refuses to submit if `main` no longer matches what was loaded, so a stale copy can't silently undo another change.
- **Verification is client-side**: The public verification page fetches the registry and performs all crypto in the browser — no server round-trip.
- **PIN security**: The Go signing app uses `piv-go` to talk directly to the YubiKey via PCSC. PIN is handled entirely in-process — never on the command line, never in a file, never visible in `/proc`.
- **QR as transport**: The QR code is a URL containing the full signed credential. No database lookup required.

### Accepted Risks

- **Distinguishable verification diagnostics (library only)**: `verifyCredential` returns distinct reasons for date- and honor-mismatch, revealing that a valid signature exists for a key whose `to` date or `allowed_honors` excludes the credential. The public page does not display reasons. Accepted — the registry is public anyway.
- **Public key registry is public**: By design. The security property is that only the holder of the YubiKey private key can produce valid signatures.
- **Reported issues never include the error log**: Report Issue (signing-failure) reports are posted to the public tracker without a preview, so they never attach the log; operators send it deliberately via Help → Export Error Log…. The error log contains only sanitized internal state (timestamps, error types, stack traces) — no credential data, PINs, or tokens.

## Data Flow

### Issuance Flow

Diagram: [docs/issuance-flow.svg](docs/issuance-flow.svg).

1. Operator opens the signing app (Go desktop binary)
2. Operator plugs in the YubiKey (signing does not require the registry; works offline)
3. Operator fills in credential form (recipient, honor, detail, date)
4. Operator clicks "Sign" → app checks the issuance log for the same payload hash; if found, it skips the PIN prompt and step 5, rebuilds the URL from the logged signature (the same QR as when it was first issued) and adds no log entry. If the issuance log cannot be read, signing is refused; logged records with a malformed signature are ignored. Otherwise it prompts for the YubiKey PIN via GUI dialog (skipped when a cached PIN is available)
5. App opens the YubiKey via PCSC (fresh session per sign), reads the certificate from PIV slot 9c, canonicalizes → signs → verifies round-trip → logs
6. App shows a PNG preview; the SVG (for print) and a 2048px PNG are generated when the operator saves them
7. Operator saves SVG, gives to diploma designer for printing

**Bulk variant:** the operator selects a CSV instead of filling the form. Every row is validated before the PIN prompt (invalid rows are skipped; rows whose payload hash is already in the issuance log are reported as already issued, with the URL rebuilt from the logged signature). The PIN is entered once; each remaining row is then signed and logged as in step 5, minus the QR preview. The batch stops at the first failed row (signing error or failed log write) and marks the remaining rows not attempted, so every signed row is either logged or reported as not logged. Rows duplicating an earlier row of the same file are rejected as invalid. The operator can export a results CSV containing each row's verification URL.

**Duplicate cleanup:** logs written before the duplicate check may hold the same credential more than once. The History tab's **Remove Duplicates…** button keeps the earliest record with a well-formed signature for each payload hash (case-insensitive) and drops later copies; records with a malformed signature before it, or with an empty hash, are kept as-is. It saves a timestamped `.bak-` copy of the log first. Log appends and this rewrite are serialized by a mutex in `log/issuance.go`.

### Verification Flow

Diagram: [docs/verification-flow.svg](docs/verification-flow.svg).

1. Anyone scans QR code on diploma with phone camera
2. Phone opens `https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>`
3. Verification page fetches the key registry and revocation list in parallel (registry failure → error state)
4. Ed25519 signature verified client-side against every registry key; on a match the credential is checked against the revocation list, then the key's `to` date and `allowed_honors`
5. Result displayed: Verified (credential details + authority, with a note if revocation status could not be checked), Credential Revoked, Not Verified, or Verification Error — all with generic text; the specific rejection reason is not shown

## Credential Revocation

Credentials can be revoked after issuance. The revocation mechanism is hash-based and privacy-preserving.

### Design

- **Revocation list** (`verify/keys/revocations.json`) is hosted on GitHub Pages alongside the key registry.
- **Privacy property**: only opaque SHA-256 hashes of credential payloads are published. No personal data or credential content is exposed.
- **Verification order**: signature is verified first; revocation is checked only after a valid signature is confirmed.
- **Soft failure**: if the revocation list cannot be fetched or fails validation (or `crypto.subtle` is unavailable), verification proceeds and a valid result shows "Revocation status could not be verified." The system does not block valid credentials due to a fetch failure.

### Desktop App (Go)

- The **History** tab includes a **Revoke** button with a confirmation dialog. Revoking a credential submits a pull request via the GitHub API (`CreateRevocationPR` in `ghapi`), adding the credential's SHA-256 hash to `revocations.json`.
- `core/revocation.go` provides `RevocationEntry`, `RevocationList`, `ValidateRevocationList`, `BuildRevocationSet`, `IsRevoked`, `IsPayloadHash`, and `AppendRevocationEntry` (deep-copies the list and appends a new entry without mutating the input).
- The PR's `revocations.json` is built inside `CreateRevocationPR` from the current file on upstream `main` (Contents API), never from the copy the History tab loaded, so a second revocation can't drop an earlier one. With several revocation PRs open, merge them one at a time; close any PR that conflicts and re-revoke. No PR is opened if the hash is already in that upstream list (`ErrAlreadyRevoked`) or if the user already has an open PR from a `revoke-<hash16>-` branch (`ErrRevocationPending`). If that open-PR check fails, the PR is opened anyway.

### Verification Page (TypeScript)

- `revocation.ts` provides `validateRevocationList`, `buildRevocationSet` and `isRevoked`.
- `verify-page.ts` fetches the revocation list via `fetchRevocationList` (using the shared `fetchAndValidate<T>` helper) and passes a `RevocationCheck` to the verification orchestrator.
- `VerifyPageResult` statuses: `'valid'`, `'revoked'`, `'invalid'`, `'error'`, `'info'` (no parameters).

## Module Architecture (TypeScript — Verification Library)

Diagram of both the TypeScript modules and the Go packages: [docs/module-architecture.svg](docs/module-architecture.svg).

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

The Go signing app generates QR codes as:
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

- **Dates:** only `to` limits validity. A credential dated after `to` fails; any earlier date verifies, including dates before `from`, so backdated honors work.
- **`allowed_honors`:** a list of exact honor titles (case-sensitive). A credential whose `honor` is not in the list fails. When absent, `null`, `[]` or all-blank, the key verifies any honor; blank items are skipped. Non-string, untrimmed or control-character items reject the registry. The restriction is retroactive — it applies to every credential the key ever signed — and per entry: every entry sharing a public key needs its own `allowed_honors`, or the unrestricted entry verifies.
- **Blank `allowed_honors` fails open (accepted risk):** an edit that blanks a restriction (`[]` or `[""]`) silently makes the key unrestricted instead of rejecting the registry. Accepted because registry edits land only via maintainer-reviewed PRs and the app's Restrictions column shows the effective value.
- **Strict verifier, tolerant app:** the verification page rejects any registry field it does not recognise, so an outdated verifier fails closed instead of silently ignoring a restriction. The Go app accepts and preserves unknown fields, so new registry fields never break installed copies.

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

### Signing (Go app)

YubiKey PIV slot 9c via `go-piv/piv-go` v2 — direct PCSC access, Ed25519 (algorithm 0xE0, requires firmware >= 5.7). PIN handled entirely in-process via `crypto.Signer` interface — never on the command line, never in a file, never visible in `/proc`. The signing tool produces a raw 64-byte signature (R || S). No DER wrapping.

### PIN Security

- PIN is prompted via a GUI dialog on each single sign and once per bulk batch (default); re-signing an already-logged credential needs no PIN
- Opt-in caching: PIN stored in `mlock`'d memory (non-swappable), protected by `sync.Mutex` with generation counter (prevents TOCTOU race on timer expiry), auto-zeroed 5 minutes after the PIN was entered (not extended by use), when caching is unticked, or on app close
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
- **Go for signing app**: Single binary, `piv-go` for direct YubiKey access (PIN in-process), `crypto/ed25519` in stdlib, Fyne for cross-platform GUI. Rust was evaluated but its `yubikey` crate lacks Ed25519 PIV support (issue #602, no progress). CGO is required on both platforms (Fyne's OpenGL driver; PCSC on macOS).
- **SVG as primary QR output**: Vector format scales perfectly for print. No pixel density concerns, no forced QR version needed.
- **Registry fetch**: remote only (10s timeout), no cache or embedded fallback. If the server is unreachable, the app opens in offline mode (signing still works, but registry-dependent features are unavailable).
- **Token lifecycle**: OAuth tokens stored in OS keychain (Linux: file fallback with 0600). 90-day local TTL enforced on session restore; expired tokens are cleared and require re-authentication. Tokens validated live against GitHub API on each app startup.
- **Cross-language compatibility**: Go `core/` package produces byte-identical canonical JSON to TypeScript. Verified by test vectors (ASCII, Georgian, NFC edge cases).
- **Build info separation**: Version string lives in `buildinfo.Version` (set via `-ldflags` at build time). `buildinfo.IsDebug()` / `buildinfo.IsRelease()` mark debug builds (the startup log line is tagged "(debug mode)"). The error log (`debug.log`) is always on, captures the stdlib `log` output, and is pruned to 30 days at startup.
- **Panic recovery**: the main goroutine has a deferred `recover()` that writes the panic to the error log and stderr, then re-panics. Goroutines launched via `safeGo` (version check, signing) log the panic and show an error dialog instead of crashing; other background goroutines have no recovery.
- **Auto error reporting**: The `errorreport` package builds sanitized issue bodies (version, OS, error — no error log) and files them via the GitHub API if the user is logged in, or falls back to a pre-filled browser URL. Issue titles are prefixed `[Auto]` with labels `bug` + `auto-reported`.
