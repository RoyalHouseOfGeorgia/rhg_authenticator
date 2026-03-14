# Architecture

## System Overview

The RHG Authenticator is a credential verification system with three principals:

- **Issuer** (the Prince) — Signs credentials with a hardware security key (YubiKey)
- **Holder** (the recipient) — Receives a physical diploma with a QR code
- **Verifier** (anyone) — Scans the QR code to verify authenticity via a public web page

No blockchain, no third-party verification services. Trust is rooted in Ed25519 public key cryptography and a public key registry hosted alongside the verification page.

## Components

The system has two independent components:

1. **Verification library + page (TypeScript)** — core crypto, credential validation, key registry, and the public-facing verification page on GitHub Pages. This is what the world sees.
2. **Signing app (Go)** — self-contained desktop application with Fyne GUI. Talks directly to YubiKey via PCSC (`piv-go`), signs credentials, generates QR codes (SVG/PNG). Single binary, no external tools required. See [go/README.md](go/README.md) for details.

## Threat Model

- **Trust anchor**: The YubiKey hardware token. Private key never leaves the device.
- **Public registry**: `keys/registry.json` is hosted on GitHub Pages. Integrity is protected by GitHub account access controls.
- **Verification is client-side**: The public verification page fetches the registry and performs all crypto in the browser — no server round-trip.
- **PIN security**: The Go signing app uses `piv-go` to talk directly to the YubiKey via PCSC. PIN is handled entirely in-process — never on the command line, never in a file, never visible in `/proc`.
- **QR as transport**: The QR code is a URL containing the full signed credential. No database lookup required.

### Accepted Risks

- **Timing side channel in verification diagnostics**: Date-mismatch diagnostics reveal whether a valid signature exists outside the date range. This is intentional UX — the registry is public anyway.
- **Public key registry is public**: By design. The security property is that only the holder of the YubiKey private key can produce valid signatures.

## Data Flow

### Issuance Flow

1. Operator opens the signing app (Go desktop binary)
2. App detects YubiKey via PCSC, reads certificate from PIV slot 9c
3. App fetches registry, matches YubiKey public key to authority
4. Operator fills in credential form (recipient, honor, detail, date)
5. Operator clicks "Sign" → app prompts for YubiKey PIN via GUI dialog
6. App canonicalizes credential → signs via YubiKey → verifies round-trip → logs
7. App generates QR code (SVG for print, PNG for preview)
8. Operator saves SVG, gives to diploma designer for printing

### Verification Flow

1. Anyone scans QR code on diploma with phone camera
2. Phone opens `https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>`
3. Verification page fetches key registry
4. Ed25519 signature verified client-side in browser
5. Result displayed: valid credential details or rejection reason

## Module Architecture (TypeScript — Verification Library)

| Module | Responsibility | External Deps |
|--------|---------------|---------------|
| `canonical.ts` | Deterministic JSON serialization (key-sort, NFC, no whitespace) | None |
| `base64url.ts` | Base64URL encode/decode, standard Base64 decode | None (uses `btoa`/`atob`) |
| `credential.ts` | Credential v1 schema validation, control char rejection, field length limits, `sanitizeForError` | `validation.ts` |
| `crypto.ts` | Ed25519 sign, verify (`zip215: false`), getPublicKey | `@noble/curves` |
| `registry.ts` | Registry schema validation, authority lookup, SPKI key decoding | `base64url.ts`, `validation.ts` |
| `validation.ts` | Shared date validation (calendar-correct, no `Date` constructor) | None |
| `verify.ts` | Single-pass verification orchestrator | `credential.ts`, `crypto.ts`, `registry.ts` |
| `index.ts` | Barrel export | All core modules |
| `verify-page.ts` | Browser verification page: URL parsing, registry fetch, DOM rendering | `verify.ts`, `base64url.ts`, `registry.ts` |

## Credential Format

### Schema (v1)

```typescript
type CredentialV1 = {
  authority: string;   // Formal title of the signer
  date: string;        // ISO 8601 date (YYYY-MM-DD)
  detail: string;      // Specific distinction or rank
  honor: string;       // Title of the honor bestowed
  recipient: string;   // Full name of the recipient
  version: 1;          // Schema version
};
```

All six fields are required. No extra fields allowed. Strings must be non-empty with no leading/trailing whitespace, no control characters (C0/C1/bidi), and within per-field length limits (authority: 200, recipient: 500, honor: 200, detail: 2000, date: 10).

### Canonical Form

Before signing, the credential is serialized to canonical JSON:

1. Object keys sorted lexicographically at all levels
2. Strings NFC-normalized (Unicode normalization) — both keys and values
3. No whitespace between tokens
4. Standard JSON escaping per RFC 8259 §7 (including U+2028/U+2029)

The canonical bytes are what gets signed and included in the URL (not a re-serialization).

### URL Encoding

```
https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>
```

- `p` = Base64URL(canonical JSON bytes)
- `s` = Base64URL(64-byte Ed25519 signature)

Maximum URL length: 625 chars (conservative limit within QR error correction Q capacity).

### QR Code

The Go signing app generates QR codes as:
- **SVG** (primary) — vector format, scales to any print size without quality loss. The diploma designer imports the SVG and scales to fit.
- **PNG** (preview) — 512px for on-screen display, 2048px for download.

Error correction level Q (25% recovery, `qrcode.High` in the `skip2/go-qrcode` library). Version auto-selected (smallest that fits the URL). Minimum recommended print size: 3×3 cm (encoded in the default SVG filename as `min3cm`).

## Key Registry

### Schema

```typescript
type KeyEntry = {
  authority: string;        // Must match credential's authority field
  from: string;             // Start of validity (YYYY-MM-DD, inclusive)
  to: string | null;        // End of validity (inclusive) or null (no expiration)
  algorithm: 'Ed25519';     // Only Ed25519 supported
  public_key: string;       // Base64: 44-byte SPKI DER or 32-byte raw
  note: string;             // Human-readable description
};

type Registry = { keys: KeyEntry[] };
```

### Key Rotation

The registry supports multiple keys per authority with non-overlapping date ranges. Verification tries all matching keys in a single pass, with date-mismatch diagnostics for valid-but-expired signatures.

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

- PIN is prompted via a GUI dialog on each sign operation (default)
- Opt-in caching: PIN stored in `mlock`'d memory (non-swappable), protected by `sync.Mutex`, auto-zeroed after 5 minutes of inactivity or app close
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
| Strict crypto inputs | `crypto.ts` | Length validation on all key/signature/message inputs |
| SPKI prefix verification | `registry.ts` | Byte-by-byte comparison of 12-byte DER header |

## Design Decisions

- **Sync API**: All crypto operations are synchronous. `@noble/curves` is pure JS — no Web Crypto async overhead.
- **No key_id field**: The registry is too small for O(n) lookup to matter. Signature verification is the real authentication gate.
- **Arithmetic date validation**: Uses manual month/day/leap-year checks instead of `Date` constructor, which silently rolls invalid dates (e.g., Feb 30 → Mar 2).
- **Single-pass verification**: Verify signature against all authority-matching keys, with date-mismatch diagnostics for valid-but-expired matches.
- **Go for signing app**: Single binary, `piv-go` for direct YubiKey access (PIN in-process), `crypto/ed25519` in stdlib, Fyne for cross-platform GUI. Rust was evaluated but its `yubikey` crate lacks Ed25519 PIV support (issue #602, no progress). CGO required on macOS/Linux for PCSC; pure Go on Windows.
- **SVG as primary QR output**: Vector format scales perfectly for print. No pixel density concerns, no forced QR version needed.
- **Registry fallback chain**: remote (10s timeout) → cached file → embedded (go:embed). Corrupted cache falls through to embedded without terminating.
- **Cross-language compatibility**: Go `core/` package produces byte-identical canonical JSON to TypeScript. Verified by test vectors (ASCII, Georgian, NFC edge cases).
