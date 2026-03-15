# Developer Guide

This guide covers the **TypeScript verification library**. For the Go signing app, see [go/README.md](go/README.md).

## Prerequisites

- Node.js 20+
- npm (ships with Node.js)

## Setup

```bash
git clone <repo-url>
cd rhg_authenticator
npm install
```

## Scripts

| Command | Description |
|---------|-------------|
| `npm test` | Run all tests (vitest) |
| `npm run test:watch` | Run tests in watch mode |
| `npm run lint` | Type-check without emitting (`tsc --noEmit`) |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm run build:verify` | Bundle verification page JS (`verify/verify.js`) |
| `npm run audit:deps` | Run `npm audit` on production dependencies |

## Project Structure

```
src/
├── canonical.ts          # Deterministic JSON serializer
├── base64url.ts          # Base64URL + standard Base64 codecs
├── credential.ts         # Credential v1 schema validation + sanitizeForError
├── crypto.ts             # Ed25519 sign/verify/getPublicKey
├── registry.ts           # Key registry schema, lookup, decoding
├── validation.ts         # Shared date validation utilities
├── verify.ts             # Verification orchestrator
├── verify-page.ts        # Verification page logic (URL parsing, fetch, render)
├── index.ts              # Barrel export
└── __tests__/
    ├── helpers.ts              # Shared test utilities (makeKeypair, makeKeyEntry, makeRegistry)
    ├── fixtures/
    │   └── vectors.json        # Cross-language test vectors (synced with go/testdata/)
    ├── canonical.test.ts
    ├── base64url.test.ts
    ├── credential.test.ts
    ├── cross-language.test.ts  # Verifies canonical output + signatures match Go
    ├── crypto.test.ts
    ├── registry.test.ts
    ├── validation.test.ts
    ├── verify.test.ts
    └── verify-page.test.ts
verify/
├── index.html            # Static verification page shell
├── styles.css            # Mobile-first CSS
├── verify.js             # esbuild IIFE bundle (built artifact)
├── favicon.ico           # Site favicon
└── royal-arms-120.png    # Royal arms crest (120x120)
scripts/
└── generate-test-url.ts  # Generate signed test URLs for UI preview
keys/
└── registry.json         # Public key registry (development + maintenance key)
```

## API Reference

### Canonical JSON

```typescript
canonicalize(obj: JsonObject): Uint8Array
```

Produces deterministic UTF-8 bytes from a JSON object. Keys are recursively sorted, strings are NFC-normalized, no extraneous whitespace. Rejects `__proto__` keys, `undefined` values, non-finite numbers, and negative zero.

### Base64 Encoding

```typescript
base64urlEncode(bytes: Uint8Array): string      // → unpadded Base64URL
base64urlDecode(str: string): Uint8Array         // ← padded or unpadded Base64URL
base64Decode(str: string): Uint8Array            // ← standard padded Base64
```

`base64urlDecode` rejects invalid-length inputs (remainder 1 after removing padding).

### Credential Validation

```typescript
validateCredential(obj: unknown): Credential
```

Validates and type-narrows an unknown value as a v1 credential. Checks:
- Required fields: `version`, `date`, `detail`, `honor`, `recipient`
- `version` must be `1` (throws `UnsupportedVersionError` for other numbers)
- String fields: non-empty, no leading/trailing whitespace, no control characters (C0/C1/bidi)
- Per-field length limits: recipient (500), honor (200), detail (2000), date (10)
- Date: arithmetic validation (leap years, month lengths) — not `Date` constructor
- No extra fields

### Crypto

```typescript
sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array       // 64-byte signature
verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
getPublicKey(secretKey: Uint8Array): Uint8Array                    // 32-byte public key
```

Thin wrappers around `@noble/curves/ed25519`. Verify uses strict RFC 8032 mode (`zip215: false`). All inputs are length-validated.

### Key Registry

```typescript
validateRegistry(obj: unknown): Registry
isDateInRange(credentialDate: string, key: KeyEntry): boolean
decodePublicKey(entry: KeyEntry): Uint8Array   // SPKI DER or raw → 32 bytes
```

- `validateRegistry` rejects extra fields at both top-level and entry-level
- `decodePublicKey` accepts 44-byte SPKI DER (strips 12-byte prefix) or 32-byte raw keys

### Verification Orchestrator

```typescript
verifyCredential(
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
  registry: Registry,
): VerificationResult

type VerificationResult =
  | { valid: true; key: KeyEntry; credential: Credential }
  | { valid: false; reason: string }
```

Full verification pipeline:
1. Enforce payload size limit (`MAX_PAYLOAD_BYTES = 2048`)
2. Parse JSON, validate credential schema
3. Try all registry keys; authority derived from matching key
4. Single-pass: verify signature against all keys; track date-mismatch diagnostics
5. Return typed result with matching key or failure reason

### Verification Page

```typescript
parseParams(search: string): PageParams | ParseError
getRegistryUrl(): string
fetchRegistry(url: string): Promise<Registry>
runVerification(params: PageParams, registry: Registry): VerifyPageResult
renderResult(result: VerifyPageResult, container: Element): void
initVerifyPage(): Promise<void>
```

Client-side verification page logic. Parses URL parameters (`?p=<payload>&s=<signature>`), fetches the key registry, runs cryptographic verification, and renders the result into the DOM. All text is set via `textContent` (never `innerHTML`) to prevent XSS. Registry URL is absolute only on `verify.royalhouseofgeorgia.ge`; relative path everywhere else.

### Building the Verification Page

```bash
npm run build:verify    # esbuild → verify/verify.js (IIFE, es2020, minified)
```

To preview locally:

```bash
npx tsx scripts/generate-test-url.ts   # prints test URLs
npx http-server . -p 8080              # serve from project root
```

## Usage Example

### Verifying

```typescript
import { verifyCredential, validateRegistry, base64urlDecode } from '@rhg/authenticator';

const registry = validateRegistry(JSON.parse(registryJson));
const payload = base64urlDecode(params.get('p')!);
const signature = base64urlDecode(params.get('s')!);

const result = verifyCredential(payload, signature, registry);
if (result.valid) {
  console.log('Verified! Authority:', result.key.authority);
} else {
  console.log('Rejected:', result.reason);
}
```

## Testing Conventions

- Tests live in `src/__tests__/`
- Shared test utilities in `src/__tests__/helpers.ts` (`makeKeypair`, `makeKeyEntry`, `makeRegistry`, `validCredentialObj`)
- Use `describe`/`it` blocks with descriptive names
- Test both happy paths and error cases
- Credential test data uses realistic but fictional values
- Crypto tests use the RFC 8032 empty-message test vector (`d75a980182b10ab7...`)
- No mocking of internal modules — tests exercise the real code paths
- Verification page tests use `// @vitest-environment happy-dom` per-file directive
- `fetch` is mocked via `vi.stubGlobal('fetch', vi.fn())` in verify-page tests
- 305 tests total (9 test files)

## Key Registry Format

The `keys/registry.json` file contains the development/maintenance key. To add a production key:

1. Generate an Ed25519 key on YubiKey PIV slot 9c (see [go/README.md](go/README.md#yubikey-setup))
2. Open the **Registry** tab in the signing app
3. Click **"Import from YubiKey"** (or import a `.crt`/`.pem` file via **"Import Certificate"**)
4. Set `authority` to the formal title, `from` to the activation date, `to` to `null` for an active key
5. Save and commit the updated `keys/registry.json`
