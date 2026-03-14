# RHG Authenticator — Desktop Signing App

Self-contained desktop application for signing Royal House of Georgia credentials. Produces QR codes (SVG for print, PNG for preview) that are verified by the public verification page.

## Requirements

- Go 1.24+
- YubiKey with Ed25519 key in PIV slot 9c (firmware >= 5.7)

### Platform-Specific

| Platform | PCSC | GUI | Extra Packages |
|----------|------|-----|----------------|
| **macOS** | Built-in (PCSC framework) | Built-in (OpenGL) | None |
| **Windows** | Built-in (WinSCard) | Built-in (OpenGL) | None |
| **Linux** | Requires `pcscd` | Requires OpenGL/X11 dev libs | `sudo apt install libpcsclite-dev libgl1-mesa-dev xorg-dev pcscd` |

## Build

```bash
make build          # → release/rhg-authenticator
make test           # Run all Go tests
make vet            # Static analysis
make checksums      # Generate SHA256SUMS.txt
make clean          # Remove release directory
```

The binary embeds the version from `git describe --tags`.

## Usage

1. Run `./release/rhg-authenticator`
2. The app opens immediately with two tabs: **Sign** and **History** (no YubiKey needed yet)

### Sign Tab

1. Fill in the credential form:
   - **Recipient**: full name
   - **Honor**: select from the dropdown (5 recognized titles)
   - **Detail**: specific distinction or rank
   - **Date**: YYYY-MM-DD (defaults to today)
2. Plug in your YubiKey
3. Click **Sign Credential**
4. Enter your YubiKey PIN when prompted
   - Check "Remember PIN for this session" to cache the PIN (opt-in, mlock'd memory, auto-clears after 5 minutes)
4. The QR code appears as a preview
5. Click **Save SVG** (primary — vector for print) or **Save PNG** (2048px alternative)
6. Copy the verification URL to clipboard via **Copy URL**

### History Tab

Browse previously issued credentials. Search by recipient name. Click any entry for full details.

## YubiKey Setup

### Generate Ed25519 Key (one-time)

```bash
# Generate key in PIV slot 9c
yubico-piv-tool -s 9c -a generate -A ED25519 -o public.pem

# Create self-signed certificate
yubico-piv-tool -s 9c -a verify-pin -a selfsign-certificate \
  -S "/CN=RHG Credential Signing" -i public.pem -o cert.pem

# Import certificate back to YubiKey
yubico-piv-tool -s 9c -a import-certificate -i cert.pem
```

### Export Public Key for Registry

```bash
yubico-piv-tool -a read-certificate -s 9c | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  base64
```

Add the Base64 string as `public_key` in `keys/registry.json`.

## Key Registry

The app fetches the key registry from `https://verify.royalhouseofgeorgia.ge/keys/registry.json` on startup. Fallback chain:

1. **Remote** (10s timeout, single attempt)
2. **Cached** (`~/.rhg-authenticator/registry.cache.json` on macOS/Linux, `%AppData%\rhg-authenticator\` on Windows)
3. **Embedded** (bundled at build time from `go/keys/registry.json`)

If all sources fail, the app shows an error and exits.

## Security

- **PIN never leaves the process**: `piv-go` talks directly to the YubiKey via PCSC. No subprocess, no command-line arguments, no `/proc` exposure.
- **PIN caching** (opt-in): stored in `mlock`'d memory (non-swappable), protected by mutex, auto-zeroed after 5 minutes of inactivity.
- **Post-sign verification**: every signature is verified immediately after signing to catch hardware errors.
- **Atomic log writes**: issuance records use tmp-file + rename pattern for crash safety.

## Architecture

```
go/
├── main.go              # App entry point, Fyne window, startup sequence
├── core/                # Credential logic (must match TypeScript byte-for-byte)
│   ├── canonical.go     # Deterministic JSON (key-sort, NFC, no whitespace)
│   ├── base64url.go     # Base64URL encode/decode
│   ├── credential.go    # Credential v1 validation
│   ├── registry.go      # Key registry schema + lookup
│   ├── date.go          # Calendar-correct date validation
│   └── sign.go          # Signing orchestrator
├── gui/                 # Fyne GUI
│   ├── sign_tab.go      # Credential form + QR display
│   ├── history_tab.go   # Issuance log browser
│   └── pindialog.go     # PIN entry dialog (goroutine-safe)
├── yubikey/             # YubiKey hardware adapter
│   ├── adapter.go       # piv-go PIV signing
│   ├── pincache.go      # Secure PIN cache (mlock + mutex)
│   ├── mlock_unix.go    # mlock for macOS/Linux
│   └── mlock_windows.go # VirtualLock for Windows
├── qr/                  # QR code generation
│   └── generate.go      # SVG (vector) + PNG output
├── log/                 # Issuance log
│   └── issuance.go      # Atomic append-only JSON log
├── registry/            # Registry fetch
│   └── fetch.go         # Remote → cache → embedded fallback
├── keys/                # Embedded registry (go:embed)
│   └── registry.json
├── testdata/            # Cross-language test vectors
│   └── vectors.json
├── Makefile
├── go.mod
└── go.sum
```

## Cross-Language Compatibility

The Go `core/` package produces byte-identical output to the TypeScript verification library. This is verified by cross-language test vectors in `testdata/vectors.json` (generated from TypeScript, validated in Go). Credentials signed by the Go app verify correctly on the TypeScript verification page.
