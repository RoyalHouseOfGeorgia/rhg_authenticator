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
| `npm run build:issuer` | Bundle issuer page JS (`issuer/issuer.js`) |
| `npm run build:all` | Run all three builds (TypeScript + verify + issuer) |
| `npm run start:server` | Start signing server (`src/server/cli.ts`) |
| `npm run check:registry` | Verify no test keys in `keys/registry.json` |
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
├── issuer.ts             # Pure issuer logic: QR/URL constants, form validation, error formatting
├── issuer-page.ts        # Browser issuer page: auth, form, QR rendering, download/copy
├── index.ts              # Barrel export
├── server/
│   ├── types.ts          # Shared types: SigningAdapter, ServerConfig, IssuanceRecord
│   ├── cli.ts            # CLI entry point + argument parsing (--port, --token-file)
│   ├── main.ts           # Server startup orchestrator
│   ├── http.ts           # HTTP request handler, static file serving, CORS, rate limiting
│   ├── sign.ts           # Signing orchestrator (validate → canonicalize → sign → verify → log)
│   ├── signature.ts      # Ed25519 signature length validation
│   ├── registry-fetch.ts # Registry fetch with SSRF + DNS resolution protection + local fallback
│   ├── key-match.ts      # Public key ↔ registry entry matching
│   ├── log.ts            # Atomic append-only issuance log
│   └── yubikey.ts        # YubiKey PIV adapter (yubico-piv-tool)
└── __tests__/
    ├── helpers.ts         # Shared test utilities (makeKeypair, makeKeyEntry, makeRegistry)
    ├── canonical.test.ts
    ├── base64url.test.ts
    ├── credential.test.ts
    ├── crypto.test.ts
    ├── registry.test.ts
    ├── validation.test.ts
    ├── verify.test.ts
    ├── verify-page.test.ts
    ├── issuer.test.ts
    ├── issuer-page.test.ts  # happy-dom DOM tests
    ├── issuer-qr.test.ts    # QR encode/decode round-trip tests
    └── server/
        ├── cli.test.ts
        ├── http.test.ts
        ├── key-match.test.ts
        ├── log.test.ts
        ├── main.test.ts
        ├── registry-fetch.test.ts
        ├── sign.test.ts
        ├── sign-verify-throw.test.ts
        ├── signature.test.ts
        └── yubikey.test.ts
issuer/
├── index.html            # Issuer interface HTML shell
├── styles.css            # Issuer-specific CSS (shared design tokens with verify)
└── issuer.js             # esbuild IIFE bundle (built artifact)
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
- String fields: non-empty, no leading/trailing whitespace, no control characters (C0/C1/bidi)
- Per-field length limits: authority (200), recipient (500), honor (200), detail (2000), date (10)
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
4. Single-pass: verify signature against all matching keys; track date-mismatch diagnostics
5. Return typed result with matching key or failure reason

Failure reasons:
- `'payload exceeds maximum size'`
- `'payload is not valid JSON'`
- `'payload must be a JSON object'`
- `'credential version not supported'`
- `'credential validation failed: ...'`
- `'authority not found in registry'`
- `'signature valid but credential date outside key validity period'`
- `'no matching key produced a valid signature'`

### Signing Server

```typescript
startServer(options?: {
  config?: Partial<ServerConfig>;
  adapter?: SigningAdapter;
  now?: Date;
  tokenFilePath?: string;
}): Promise<{ server: http.Server; port: number; token: string; close: () => void }>
```

Starts the localhost signing server. Generates a random bearer token, exports the YubiKey public key, fetches and validates the registry, resolves the authority name from the key, and starts an HTTP server with background registry refresh (60s interval).

**`ServerConfig` fields:**
- `port` (default `3141`), `host` (default `'127.0.0.1'`)
- `registryUrl` — remote registry URL (HTTPS required, SSRF-validated)
- `localRegistryPath` — fallback local registry file
- `logPath` — path to `issuances.json`
- `issuerDir` — directory for static issuer HTML (`null` = placeholder)
- `authority` — resolved at startup from registry match

**HTTP Endpoints:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | Optional | Unauthenticated: `{ "status": "ok" }`. With valid Bearer: `{ "status": "ok", "authority": "...", "authenticated": true }` |
| `POST` | `/sign` | Bearer token + Origin header | Sign a credential → `{ signature, payload, url }` |
| `GET` | `/*` | No | Serve static files from `issuerDir` (issuer HTML/CSS/JS) |

**POST /sign** request body:
```json
{ "recipient": "...", "honor": "...", "detail": "...", "date": "YYYY-MM-DD" }
```

**Security features:**
- Bearer token auth with SHA-256 timing-safe comparison
- Origin header required on all POST requests (localhost origins only)
- Auth-failure rate limiting with exponential backoff (5 failures → backoff, max 30s)
- 64KB body size limit, 5s body read timeout
- Signing queue depth limit (5 concurrent)
- Sign request body extra-key rejection
- SSRF protection on registry URL (HTTPS-only, hostname blocklist, pre-fetch DNS resolution with IPv4/IPv6 private range detection)
- TOCTOU-safe static file serving via fd-based reads
- CSP (`base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy headers
- Token fingerprint (SHA-256) in startup banner — raw token never logged
- Optional `--token-file` for operators who redirect stderr
- Authority re-checked on background registry refresh with revocation warning
- Stderr accumulation capped at 64KB in child process spawning

### CLI

```bash
npx tsx src/server/cli.ts [--port <number>] [--token-file <path>] [--help]
# Or: npm run start:server
```

| Flag | Description |
|------|-------------|
| `--port <number>` | Port to listen on (env: `RHG_PORT`, default: 3141) |
| `--token-file <path>` | Write bearer token to file instead of stderr (0o600 permissions) |
| `--help` | Show usage |

Port can also be set via `RHG_PORT` environment variable. Handles SIGTERM and SIGINT for clean shutdown.

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

### Issuer Logic

```typescript
computeUrlLength(fields: FormFields, authority: string): UrlLengthResult
validateFormFields(fields: FormFields): string | null
formatSignError(status: number, body: SignErrorBody | undefined): string
```

Pure issuer logic with no DOM access:
- `computeUrlLength` estimates the full verification URL length using the same canonicalization pipeline as the server's `handleSign`, returning `{ estimatedLength, maxLength: 625, fits: boolean }`
- `validateFormFields` checks required fields, honor title membership, and date validity — returns `null` when valid or an error message string
- `formatSignError` maps HTTP status codes to user-friendly error messages; truncates `body.error` to 200 chars for 400 responses

**Constants:** `QR_VERSION = 24`, `QR_MAX_URL_LENGTH = 625`, `QR_MODULES = 113`, `HONOR_TITLES` (5 entries), `DOM_IDS` (HTML↔JS contract)

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

- Tests live in `src/__tests__/` (core) and `src/__tests__/server/` (server modules)
- Shared test utilities in `src/__tests__/helpers.ts` (`makeKeypair`, `makeKeyEntry`, `makeRegistry`, `validCredentialObj`)
- Use `describe`/`it` blocks with descriptive names
- Test both happy paths and error cases
- Credential test data uses realistic but fictional values
- Crypto tests use the RFC 8032 empty-message test vector (`d75a980182b10ab7...`)
- No mocking of internal modules — tests exercise the real code paths
- Verification and issuer page tests use `// @vitest-environment happy-dom` per-file directive
- `fetch` is mocked via `vi.stubGlobal('fetch', vi.fn())` in verify-page, issuer-page, and registry-fetch tests
- `QRCode` is mocked via `vi.mock('qrcode')` in issuer-page tests (happy-dom has no real canvas)
- QR round-trip tests (`issuer-qr.test.ts`) use `qrcode` + `jsqr` + `canvas` in Node environment
- `dns.promises.lookup` is mocked in registry-fetch tests for SSRF DNS resolution testing
- Server tests use mock `SigningAdapter` implementations — no YubiKey required
- HTTP tests use Node's `http.request` against a real in-process server instance
- 656 tests total (21 test files)

## Key Registry Format

The `keys/registry.json` file currently contains a placeholder entry. For production:

1. Generate an Ed25519 key on YubiKey PIV slot 9c
2. Export the public key: `yubico-piv-tool -a read-certificate -s 9c | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | base64`
3. Add the Base64 string as `public_key` in a new registry entry
4. Set `authority` to the Prince's formal title
5. Set `from` to the key activation date, `to` to `null` for an active key

See `research/signing-tool.md` for full YubiKey command reference.
