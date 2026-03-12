# Architecture

## System Overview

The RHG Authenticator is a credential verification system with three principals:

- **Issuer** (the Prince) — Signs credentials with a hardware security key (YubiKey)
- **Holder** (the recipient) — Receives a physical diploma with a QR code
- **Verifier** (anyone) — Scans the QR code to verify authenticity via a public web page

No blockchain, no third-party verification services. Trust is rooted in Ed25519 public key cryptography and a public key registry hosted alongside the verification page.

## Threat Model

- **Trust anchor**: The YubiKey hardware token. Private key never leaves the device.
- **Public registry**: `keys/registry.json` is hosted on GitHub Pages. Integrity is protected by GitHub account access controls.
- **No server-side state**: Verification is entirely client-side. The verification page fetches the registry and performs all crypto in the browser.
- **QR as transport**: The QR code is a URL containing the full signed credential. No database lookup required.

### Accepted Risks

- **Timing side channel in two-pass verification**: The second diagnostic pass reveals whether a valid signature exists outside the date range. This is intentional UX — the registry is public anyway.
- **Verbose validation errors**: Schema validation returns structured error details. The Phase 3 server will decide what to expose to end users.
- **Public key registry is public**: By design. The security property is that only the holder of the YubiKey private key can produce valid signatures.

## Data Flow

### Issuance Flow (Phase 3-4)

```
┌─────────────┐   credential JSON    ┌─────────────────┐
│ Issuer Form │────────────────────▶│ Signing Server  │
│ (browser)   │                      │ (localhost)     │
└─────────────┘                      └────────┬────────┘
                                              │ canonical JSON bytes
                                              ▼
                                     ┌─────────────────┐
                                     │ YubiKey PIV 9c  │
                                     │ Ed25519 sign    │
                                     └────────┬────────┘
                                              │ 64-byte signature
                                              ▼
                                     ┌─────────────────┐
                                     │ Base64URL encode│
                                     │ → QR code URL   │
                                     └─────────────────┘
```

### Verification Flow (Phase 2)

```
┌────────────┐   scan    ┌─────────────────────────────────────────┐
│ QR Code    │──────────▶│ https://verify.../  ?p=...&s=...       │
└────────────┘           └────────────────────┬────────────────────┘
                                              │
                         ┌────────────────────▼────────────────────┐
                         │ 1. Parse URL params (p, s)              │
                         │ 2. Base64URL decode → bytes             │
                         │ 3. Fetch /keys/registry.json            │
                         │ 4. Parse + validate credential JSON     │
                         │ 5. Find keys by authority               │
                         │ 6. Verify Ed25519 signature             │
                         │ 7. Check date range                     │
                         │ 8. Display result                       │
                         └─────────────────────────────────────────┘
```

## Module Architecture

```
                        ┌─────────────┐
                        │  verify.ts  │  Orchestrator
                        └──────┬──────┘
                   ┌───────────┼───────────┐
                   ▼           ▼           ▼
            ┌─────────────┐ ┌──────────┐ ┌───────────┐
            │credential.ts│ │crypto.ts │ │registry.ts│
            └─────────────┘ └──────────┘ └─────┬─────┘
                                               │
                   ┌───────────────────────────┘
                   ▼           ▼
            ┌────────────┐ ┌──────────────┐
            │base64url.ts│ │canonical.ts  │
            └────────────┘ └──────────────┘
```

### Module Responsibilities

| Module | Responsibility | External Deps |
|--------|---------------|---------------|
| `canonical.ts` | Deterministic JSON serialization (key-sort, NFC, no whitespace) | None |
| `base64url.ts` | Base64URL encode/decode, standard Base64 decode | None (uses `btoa`/`atob`) |
| `credential.ts` | Credential v1 schema validation, arithmetic date checking | None |
| `crypto.ts` | Ed25519 sign, verify (`zip215: false`), getPublicKey | `@noble/curves` |
| `registry.ts` | Registry schema validation, authority lookup, SPKI key decoding | `base64url.ts` |
| `verify.ts` | Two-pass verification orchestrator | `credential.ts`, `crypto.ts`, `registry.ts` |
| `index.ts` | Barrel export | All modules |
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

All six fields are required. No extra fields allowed. Strings must be non-empty with no leading/trailing whitespace.

### Canonical Form

Before signing, the credential is serialized to canonical JSON:

1. Object keys sorted lexicographically at all levels
2. Strings NFC-normalized (Unicode normalization)
3. No whitespace between tokens
4. Standard JSON escaping

The canonical bytes are what gets signed and included in the URL (not a re-serialization).

### URL Encoding

```
https://verify.royalhouseofgeorgia.ge/?p=<payload>&s=<signature>
```

- `p` = Base64URL(canonical JSON bytes)
- `s` = Base64URL(64-byte Ed25519 signature)

Total URL must fit within QR Version 18-Q byte capacity (394 chars). Fixed overhead is ~132 chars, leaving ~262 chars (~196 bytes) for the payload.

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

The registry supports multiple keys per authority with non-overlapping date ranges:

```json
{
  "keys": [
    { "authority": "Prince", "from": "2025-01-01", "to": "2025-12-31", "public_key": "..." },
    { "authority": "Prince", "from": "2026-01-01", "to": null, "public_key": "..." }
  ]
}
```

Verification first tries date-eligible keys. If no match, tries remaining keys and reports a date-mismatch diagnostic if a signature validates outside its key's date range.

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

`@noble/curves` was chosen over `@noble/ed25519` because v2 of the latter removed the `zip215: false` option.

### Signing

- **Production**: YubiKey PIV slot 9c via `yubico-piv-tool` (requires PIN + touch)
- **Test/CI**: `@noble/curves` in-memory signing with test keypairs

The signing tool produces a raw 64-byte signature (R ‖ S). No DER wrapping.

### Verification

Verification operates on the original payload bytes, not a re-canonicalized form. This prevents any normalization differences between signing and verification from causing false rejections.

## Security Hardening

### Implemented Defenses

| Defense | Module | Description |
|---------|--------|-------------|
| Prototype pollution | `canonical.ts` | `Object.create(null)` for sorted objects; `__proto__` key rejected |
| Payload size limit | `verify.ts` | `MAX_PAYLOAD_BYTES = 2048` enforced before JSON parsing |
| Log injection | `credential.ts`, `registry.ts` | `sanitizeForError` strips C0/C1 control characters |
| Base64 length validation | `base64url.ts` | Rejects remainder-1 inputs (never valid Base64) |
| Extra field rejection | `credential.ts`, `registry.ts` | No unexpected fields pass validation |
| Strict crypto inputs | `crypto.ts` | Length validation on all key/signature/message inputs |
| SPKI prefix verification | `registry.ts` | Byte-by-byte comparison of 12-byte DER header |

### Design Decisions

- **Sync API**: All crypto operations are synchronous. `@noble/curves` is pure JS — no Web Crypto async overhead.
- **No key_id field**: The registry is too small for O(n) lookup to matter. Signature verification is the real authentication gate.
- **Arithmetic date validation**: Uses manual month/day/leap-year checks instead of `Date` constructor, which silently rolls invalid dates (e.g., Feb 30 → Mar 2).
- **Two-pass verification**: Date-eligible keys first for correctness, then remaining keys for diagnostics. Intentional timing trade-off for better UX.

## Planned Phases

### Phase 2: Verification Page (Complete)

Static HTML/CSS/JS page for GitHub Pages at `verify/`. The Phase 1 library is bundled via esbuild into a single IIFE (39KB minified). The page parses URL parameters (`?p=<payload>&s=<signature>`), fetches the key registry, runs Ed25519 verification client-side, and renders a dignified success/failure/error UI. Mobile-first design (primary use: phone scanning QR). All DOM text via `textContent` for XSS prevention. WCAG AA accessible (color + icon + text label for all states).

### Phase 3: Signing Server

Localhost Node.js server interfacing with YubiKey. Fetches registry from GitHub for pre-sign validation. Bearer token auth. Atomic log append.

### Phase 4: Issuer Interface

Browser-based form served by the signing server. NFC-normalizes inputs, builds canonical JSON, posts to signing server, generates QR code. Validates URL length against QR capacity limit.

### Phase 5: Issuance Log

Append-only JSON log written by the signing server. Searchable history view in the issuer interface.

### Phase 6: Packaging

Platform-specific launcher script, setup guide, GitHub Pages configuration, credential v1 formal specification, README.
