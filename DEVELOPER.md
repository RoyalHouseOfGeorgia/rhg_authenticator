# Developer Guide

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

## Project Structure

```
src/
├── canonical.ts          # Deterministic JSON serializer
├── base64url.ts          # Base64URL + standard Base64 codecs
├── credential.ts         # Credential v1 schema validation
├── crypto.ts             # Ed25519 sign/verify/getPublicKey
├── registry.ts           # Key registry schema, lookup, decoding
├── verify.ts             # Verification orchestrator
├── verify-page.ts        # Verification page logic (URL parsing, fetch, render)
├── index.ts              # Barrel export
└── __tests__/
    ├── canonical.test.ts
    ├── base64url.test.ts
    ├── credential.test.ts
    ├── crypto.test.ts
    ├── registry.test.ts
    ├── verify.test.ts
    └── verify-page.test.ts  # Uses happy-dom environment
verify/
├── index.html            # Static verification page shell
├── styles.css            # Mobile-first CSS
├── verify.js             # esbuild IIFE bundle (built artifact)
├── favicon.ico           # Site favicon
└── royal-arms-120.jpg    # Royal arms crest (120x120)
scripts/
└── generate-test-url.ts  # Generate signed test URLs for UI preview
keys/
└── registry.json         # Public key registry (test key)
research/
└── signing-tool.md       # YubiKey signing research
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
- Required fields: `version`, `authority`, `date`, `detail`, `honor`, `recipient`
- `version` must be `1` (throws `UnsupportedVersionError` for other numbers)
- String fields: non-empty, no leading/trailing whitespace
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
findKeysByAuthority(registry: Registry, authority: string): KeyEntry[]
isDateInRange(credentialDate: string, key: KeyEntry): boolean
decodePublicKey(entry: KeyEntry): Uint8Array   // SPKI DER or raw → 32 bytes
```

- `validateRegistry` rejects extra fields at both top-level and entry-level
- `findKeysByAuthority` NFC-normalizes both sides; case-sensitive
- `decodePublicKey` accepts 44-byte SPKI DER (strips 12-byte prefix) or 32-byte raw keys

### Verification Orchestrator

```typescript
verifyCredential(
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
  registry: Registry,
): VerificationResult

type VerificationResult =
  | { valid: true; key: KeyEntry }
  | { valid: false; reason: string }
```

Full verification pipeline:
1. Enforce payload size limit (`MAX_PAYLOAD_BYTES = 2048`)
2. Parse JSON, validate credential schema
3. Look up authority keys in registry
4. First pass: verify signature against date-eligible keys
5. Second pass: check remaining keys for date-mismatch diagnostics
6. Return typed result with matching key or failure reason

Failure reasons:
- `'payload exceeds maximum size'`
- `'payload is not valid JSON'`
- `'payload must be a JSON object'`
- `'credential version not supported'`
- `'credential validation failed: ...'`
- `'authority not found in registry'`
- `'signature valid but credential date outside key validity period'`
- `'no matching key produced a valid signature'`

## Usage Example

### Signing (test/CI only — production uses YubiKey)

```typescript
import { canonicalize, base64urlEncode, sign, getPublicKey } from '@rhg/authenticator';

const credential = {
  authority: 'Issuing Authority',
  date: '2026-03-11',
  detail: 'Specific distinction or rank',
  honor: 'Name of Honor',
  recipient: 'Recipient Name',
  version: 1,
};

const payloadBytes = canonicalize(credential);
const signature = sign(payloadBytes, secretKey);

const url = `https://verify.royalhouseofgeorgia.ge/?p=${base64urlEncode(payloadBytes)}&s=${base64urlEncode(signature)}`;
```

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

## Testing Conventions

- Tests live in `src/__tests__/` alongside source modules
- Use `describe`/`it` blocks with descriptive names
- Test both happy paths and error cases
- Credential test data uses realistic but fictional values
- Crypto tests use the RFC 8032 empty-message test vector (`d75a980182b10ab7...`)
- No mocking of internal modules — tests exercise the real code paths
- Verification page tests use `// @vitest-environment happy-dom` per-file directive
- `fetch` is mocked via `vi.stubGlobal('fetch', vi.fn())` in verify-page tests only

## Key Registry Format

The `keys/registry.json` file currently contains a placeholder entry. For production:

1. Generate an Ed25519 key on YubiKey PIV slot 9c
2. Export the public key: `yubico-piv-tool -a read-certificate -s 9c | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | base64`
3. Add the Base64 string as `public_key` in a new registry entry
4. Set `authority` to the Prince's formal title
5. Set `from` to the key activation date, `to` to `null` for an active key

See `research/signing-tool.md` for full YubiKey command reference.
