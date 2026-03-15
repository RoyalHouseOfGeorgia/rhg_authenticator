<p align="center">
  <img src="royal-arms.png" alt="Royal Arms of Georgia" width="120" height="120">
</p>

<h1 align="center">Royal House of Georgia — Digital Honor Authenticator</h1>

<p align="center">
  Cryptographically verifiable credential system for the Royal House of Georgia.<br>
  Ed25519 signatures via YubiKey, QR codes on physical diplomas, public verification via GitHub Pages.
</p>

---

## How It Works

1. **Issuance**: The operator opens the RHG Authenticator desktop app, fills in the credential form, and signs with a YubiKey
2. **Encoding**: The signed credential is encoded into a QR code (SVG for print, PNG for preview)
3. **Verification**: Anyone scans the QR code, opening a public page that checks the signature against a key registry

## Components

| Component | Language | Status | Description |
|-----------|----------|--------|-------------|
| **Desktop app** | Go | **Complete** | Self-contained binary with Fyne GUI — 5 tabs: Sign, History, Registry, Audit, YubiKey |
| **Verification library** | TypeScript | **Complete** | Core crypto, credential validation, key registry |
| **Verification page** | TypeScript | **Complete** | Public GitHub Pages site for QR code verification |

743 tests passing (438 Go + 305 TypeScript).

## Quick Start — Signing App (Go)

**Requirements**: Go 1.24+, YubiKey with Ed25519 key in PIV slot 9c (firmware >= 5.7)

```bash
cd go
make build          # → release/rhg-authenticator
./release/rhg-authenticator
```

The app has five tabs:
- **Sign** — fill in credential form, sign with YubiKey, generate QR code
- **History** — browse previously issued credentials, search by recipient
- **Registry** — manage the key registry (import from YubiKey or .crt/.pem, add/edit entries, save JSON)
- **Audit** — view GitHub commit history of the registry file (tamper detection)
- **YubiKey** — check if the inserted YubiKey is authorized in the registry

**Platform-specific build dependencies:**
- macOS: none (PCSC framework + OpenGL built-in)
- Windows: none (WinSCard + OpenGL built-in)
- Linux: `sudo apt install libpcsclite-dev libgl1-mesa-dev xorg-dev pcscd`

See [go/README.md](go/README.md) for detailed usage and YubiKey setup.

## Quick Start — Verification Library (TypeScript)

```bash
npm install
npm test              # 305 tests
npm run lint          # tsc --noEmit
npm run build:verify  # Bundle verification page JS
```

Requires Node.js 20+.

## Documentation

- **[go/README.md](go/README.md)** — Go signing app: build, usage, YubiKey setup, platform notes
- **[DEVELOPER.md](DEVELOPER.md)** — TypeScript library: setup, API reference, testing conventions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design, security model, data flows

## Binary Integrity

Release binaries are published with SHA-256 checksums (`SHA256SUMS.txt`) and SLSA build provenance attestations.

**Verify on macOS/Linux:**
```bash
shasum -a 256 -c SHA256SUMS.txt
```

**Verify on Windows:**
```
certutil -hashfile rhg-authenticator-windows-amd64.exe SHA256
```

Compare the output with the hash in `SHA256SUMS.txt`.

## Dependencies

### Go (signing app)

| Dependency | Purpose |
|-----------|---------|
| [`go-piv/piv-go/v2`](https://github.com/go-piv/piv-go) | YubiKey PIV access (Ed25519, PCSC, PIN in-process) |
| [`fyne.io/fyne/v2`](https://fyne.io) | Cross-platform GUI |
| [`skip2/go-qrcode`](https://github.com/skip2/go-qrcode) | QR code generation (SVG + PNG) |
| `golang.org/x/text` | NFC Unicode normalization |
| Go stdlib | `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64` |

### TypeScript (verification library)

| Dependency | Purpose | Type |
|-----------|---------|------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited Ed25519 implementation | Runtime |
| `typescript`, `vitest`, `esbuild`, `happy-dom` | Build + test toolchain | Dev |

## License

Copyright 2026 Royal House of Georgia. All rights reserved.

This software is proprietary. No license is granted to use, copy, modify, or distribute this software without explicit written permission from the Royal House of Georgia.
