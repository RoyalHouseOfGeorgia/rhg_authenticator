# Royal House of Georgia — Digital Honor Authenticator

Cryptographically verifiable credential system for the Royal House of Georgia. Ed25519 signatures via YubiKey, QR codes on physical diplomas, public verification via GitHub Pages.

## How It Works

1. **Issuance**: The Prince signs a credential (recipient, honor, date) with his YubiKey (Ed25519, PIV slot 9c)
2. **Encoding**: The signed credential is encoded into a QR code printed on the physical diploma
3. **Verification**: Anyone scans the QR code, opening a public page that checks the signature against a key registry

```
┌──────────────┐     ┌─────────────┐     ┌──────────────────┐
│  Credential  │────▶│  QR Code on │────▶│  Public Verify    │
│  + Signature │     │  Diploma    │     │  Page (GH Pages)  │
└──────────────┘     └─────────────┘     └──────────────────┘
       ▲                                          │
       │                                          ▼
┌──────────────┐                        ┌──────────────────┐
│  YubiKey     │                        │  Key Registry    │
│  Ed25519     │                        │  (registry.json) │
└──────────────┘                        └──────────────────┘
```

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core crypto & data library | **Complete** (170 tests) |
| 2 | Public verification page | Not started |
| 3 | Local signing server (YubiKey) | Not started |
| 4 | Issuer interface (form + QR) | Not started |
| 5 | Issuance log & history | Not started |
| 6 | Packaging & deployment | Not started |

## Quick Start

```bash
npm install
npm test          # 170 tests
npm run lint      # tsc --noEmit
npm run build     # TypeScript → dist/
```

Requires Node.js 20+.

## Documentation

- **[DEVELOPER.md](DEVELOPER.md)** — Setup, testing, API reference, coding conventions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design, module structure, security model, data flows

## Dependencies

| Dependency | Purpose | Type |
|-----------|---------|------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited Ed25519 implementation | Runtime |
| `typescript` | Type checking and compilation | Dev |
| `vitest` | Test runner | Dev |

## License

Private. Royal House of Georgia.
