# Royal House of Georgia — Digital Honor Authenticator

Cryptographically verifiable credential system for the Royal House of Georgia. Ed25519 signatures via YubiKey, QR codes on physical diplomas, public verification via GitHub Pages.

## How It Works

1. **Issuance**: The Prince signs a credential (recipient, honor, date) with his YubiKey (Ed25519, PIV slot 9c)
2. **Encoding**: The signed credential is encoded into a QR code printed on the physical diploma
3. **Verification**: Anyone scans the QR code, opening a public page that checks the signature against a key registry

![Issuance Flow](docs/issuance-flow.svg)

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core crypto & data library | **Complete** |
| 2 | Public verification page | **Complete** |
| 3 | Local signing server (YubiKey) | **Complete** |
| 4 | Issuer interface (form + QR) | **Complete** |
| 5 | Desktop app (Electron) | Planned |
| 6 | Packaging & deployment | Planned |

656 tests passing. Eight rounds of security hardening and two code review rounds applied.

## Quick Start

```bash
npm install
npm test              # 656 tests
npm run lint          # tsc --noEmit
npm run build:all     # TypeScript + verification + issuer bundles
npm run start:server  # Start signing server (requires YubiKey)
```

Requires Node.js 20+. The signing server requires `yubico-piv-tool` and a YubiKey with Ed25519 key in PIV slot 9c.

## Documentation

- **[DEVELOPER.md](DEVELOPER.md)** — Setup, testing, API reference, coding conventions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design, module structure, security model, data flows

## Dependencies

| Dependency | Purpose | Type |
|-----------|---------|------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited Ed25519 implementation | Runtime |
| [`qrcode`](https://github.com/soldair/node-qrcode) | QR code generation (issuer page) | Dev (bundled) |
| `typescript` | Type checking and compilation | Dev |
| `vitest` | Test runner | Dev |
| `esbuild` | Bundle TypeScript for browser | Dev |
| `happy-dom` | Lightweight DOM for issuer/verification page tests | Dev |
| `tsx` | TypeScript execution for CLI entry point | Dev |
| `canvas`, `jsqr` | QR encode/decode round-trip testing | Dev |
| `@types/node`, `@types/qrcode` | Type definitions | Dev |

## License

Private. Royal House of Georgia.
