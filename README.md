<p align="center">
  <img src="verify/royal-arms-120.png" alt="Royal Arms of Georgia" width="120" height="120">
</p>

<h1 align="center">Royal House of Georgia — Digital Honor Authenticator</h1>

<p align="center">
  Cryptographically verifiable credential system for the Royal House of Georgia.<br>
  Ed25519 signatures via YubiKey, QR codes on physical diplomas, credential revocation, public verification via GitHub Pages.
</p>

---

## How It Works

1. **Issuance**: The operator opens the RHG Authenticator desktop app, fills in the credential form, and signs with a YubiKey
2. **Encoding**: The signed credential is encoded into a QR code (saved as SVG for print or high-resolution PNG; PNG preview in the app)
3. **Verification**: Anyone scans the QR code, opening a public page that checks the signature against a key registry

## Components

| Component | Language | Status | Description |
|-----------|----------|--------|-------------|
| **Desktop app** | Go | **Complete** | Self-contained binary with Fyne GUI — 5 tabs: Sign, History, Registry, Audit, YubiKey |
| **Verification library** | TypeScript | **Complete** | Core crypto, credential validation, key registry, revocation list |
| **Verification page** | TypeScript | **Complete** | Public GitHub Pages site for QR code verification |
| **Python tools** | Python | **Complete** | `scripts/rebuild_urls.py` (rebuild verification URLs from existing signatures, no YubiKey), `scripts/rhg_qr.py` (QR image from a URL), `scripts/rhg_revocation_hash.py` (revocation hash for a URL) |

1369 tests passing (912 Go + 423 TypeScript + 34 Python).

## Download & install

Download the app from the [latest release](https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/latest).

### Mac

Requires an Apple Silicon Mac (Apple menu → **About This Mac** → **Chip** says "Apple M…"). There is no Intel build; on an Intel Mac the app won't open.

1. Download **`rhg-authenticator-darwin-arm64.zip`**.
2. Open your **Downloads** folder. If you see a `.zip`, double-click it (Safari usually unzips it for you).
3. Drag **RHG Authenticator** into your **Applications** folder, then double-click it.
4. macOS says it can't verify the app. Click **Done**.
5. Right away, open **System Settings** → **Privacy & Security**, scroll down to "RHG Authenticator was blocked…", and click **Open Anyway**.
6. In the box that pops up, click **Open Anyway** again, then enter your Mac password (or use Touch ID).

If the **Open Anyway** button isn't there, double-click the app again, then go back to System Settings.

After this, the app opens normally. **Each time you install a new version you'll need to do this again:** quit the app, drag the new one into Applications, choose **Replace**, then repeat steps 4–6.

The first time you save a QR code, macOS asks whether RHG Authenticator can access your Desktop folder — click **Allow**.

### Windows

Download **`rhg-authenticator-windows-amd64.exe`** and double-click it. If Windows shows "Windows protected your PC", click **More info** → **Run anyway**.

## Quick Start — Signing App (build from source)

**Requirements**: Go 1.27.1+, YubiKey with Ed25519 key in PIV slot 9c (firmware >= 5.7)

```bash
cd go
make build          # → release/rhg-authenticator
./release/rhg-authenticator
```

The app has five tabs:
- **Sign** — fill in credential form, sign with YubiKey, generate QR code; or **Bulk Sign from File…** to sign every row of a CSV in one session
- **History** — browse previously issued credentials, search by recipient; **Revoke** a credential (log in to GitHub with an account that has Write access to this repository; the app opens a PR against the revocation list); **Export Issuance Log…** saves a copy of the log (e.g. to the Desktop); **Remove Duplicates…** removes repeat entries for the same credential
- **Registry** — manage the key registry (import from YubiKey or .crt/.pem, add/edit entries, submit as PR for review — also needs Write access)
- **Audit** — view GitHub commit history of the registry file (tamper detection)
- **YubiKey** — check if the inserted YubiKey is authorized in the registry

**Platform-specific build dependencies:**
- macOS: Xcode Command Line Tools (C compiler for cgo); PCSC framework and OpenGL are built in
- Windows: a gcc toolchain such as MinGW-w64 (C compiler for cgo); WinSCard and OpenGL are built in

See [go/README.md](go/README.md) for detailed usage and YubiKey setup.

## Quick Start — Verification Library (TypeScript)

```bash
npm install
npm test              # 423 tests
npm run lint          # tsc --noEmit
npm run build:verify  # Bundle verification page JS
```

Requires Node.js 24+.

## Rebuilding Verification URLs (Python)

`scripts/rebuild_urls.py` rebuilds verification URLs from data you already have — no YubiKey, no network, Python 3 standard library only:

```bash
# One credential: prints the URL
python3 scripts/rebuild_urls.py --payload=<p> --signature=<s>

# Every entry in a signer's issuance log → rhg-issuances-2026-09-25-urls.csv
python3 scripts/rebuild_urls.py rhg-issuances-2026-09-25.json

# A CSV with payload and signature columns → credentials-urls.csv
python3 scripts/rebuild_urls.py credentials.csv
```

- Use the `--payload=…` / `--signature=…` form: a signature can start with `-`, which the space-separated form rejects.
- To get the signer's issuance log, have them click **Export Issuance Log…** on the History tab and send you the saved file (`rhg-issuances-YYYY-MM-DD.json`). It holds every recipient's details, so keep it out of commits — `rhg-issuances-*.json` and the script's `*-urls.csv` output are gitignored if you work on them inside the checkout. The raw file is `~/Library/Application Support/rhg-authenticator/issuances.json` (macOS) or `%APPDATA%\rhg-authenticator\issuances.json` (Windows).
- File output is a UTF-8 CSV with columns `name,honor,detail,date,url` that opens in Excel. An existing output file is never overwritten.
- Each entry is checked structurally: a log entry must rebuild to its stored `payload_sha256`, and a payload must be in canonical form. Entries that fail are skipped and reported by line/entry number (exit code 1). The hash check catches corruption, not tampering — anyone who can edit the log can recompute it. Signatures are **not** verified; only the verification page proves a URL is genuine. Don't feed the output into **Bulk Sign** unless every URL in it verifies.
- Tests: `python3 -m unittest discover -s scripts`

### QR code and revocation hash

```bash
# QR code for a URL or a payload/signature pair: SVG by default, --png for PNG
python3 scripts/rhg_qr.py -o ~/Desktop/credential.svg '<verification URL>'
python3 scripts/rhg_qr.py --png -o ~/Desktop/credential.png --payload=<p> --signature=<s>

# Revocation hash for verify/keys/revocations.json (prints recipient | honor | date to stderr)
python3 scripts/rhg_revocation_hash.py '<verification URL>'
```

- `rhg_qr.py` needs [segno](https://pypi.org/project/segno/): `pip install segno` (Debian: `sudo apt install python3-segno`). It never overwrites an existing file; pass `-o` so QR images of real credentials don't land in the checkout. It uses error-correction level Q, like the app, and refuses URLs over 625 characters — the app's limit for a printable QR code.
- These two scripts are maintainer tools with no tests; changes to them don't trigger the Python test workflow (CodeQL still scans them).

## Documentation

- **[Royal House of Georgia — Digital Authenticator](Royal%20House%20of%20Georgia%20-%20Digital%20Authenticator.pdf)** — Non-technical overview: what the system does, how verification works, threat model, privacy
- **[go/README.md](go/README.md)** — Go signing app: build, usage, YubiKey setup, platform notes
- **[DEVELOPER.md](DEVELOPER.md)** — TypeScript library: setup, API reference, testing conventions
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design, security model, data flows
- **[CHANGELOG.md](CHANGELOG.md)** — Release history

## Binary Integrity

Release binaries are published with SHA-256 checksums (`SHA256SUMS.txt`) and SLSA build provenance attestations.

**Verify on macOS/Linux:**
```bash
shasum -a 256 -c --ignore-missing SHA256SUMS.txt
```

**Verify on Windows:**
```
certutil -hashfile rhg-authenticator-windows-amd64.exe SHA256
```

Compare the output with the hash in `SHA256SUMS.txt`.

**Stronger check — build provenance** (needs the [GitHub CLI](https://cli.github.com/); replace `v1.5.0` with the release's tag and the file name with the one you downloaded):
```bash
gh attestation verify rhg-authenticator-windows-amd64.exe \
  --repo RoyalHouseOfGeorgia/rhg_authenticator \
  --signer-workflow RoyalHouseOfGeorgia/rhg_authenticator/.github/workflows/build.yml \
  --source-ref refs/tags/v1.5.0
```
This proves the file was built by the release workflow from that tag. Only the maintainer can create tags, so pinning `--source-ref` rejects provenance produced from any other branch or tag. The checksums file lives on the same release page as the download, so on its own it only detects a corrupted download.

A genuine release has a `vX.Y.Z` tag (e.g. `v1.5.0`) and is published by **github-actions[bot]** — the release page shows the author. Don't install from a release that differs; the app's own update notice ignores such releases.

## Dependencies

### Go (signing app)

| Dependency | Purpose |
|-----------|---------|
| [`go-piv/piv-go/v2`](https://github.com/go-piv/piv-go) | YubiKey PIV access (Ed25519, PCSC, PIN in-process) |
| [`fyne.io/fyne/v2`](https://fyne.io) | Cross-platform GUI |
| [`skip2/go-qrcode`](https://github.com/skip2/go-qrcode) | QR code generation (SVG + PNG) |
| [`zalando/go-keyring`](https://github.com/zalando/go-keyring) | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| [`fyne.io/x/fyne`](https://github.com/fyne-io/fyne-x) | Fyne extension widgets (calendar date picker) |
| `golang.org/x/text` | NFC Unicode normalization |
| Go stdlib | `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64` |

### TypeScript (verification library)

| Dependency | Purpose | Type |
|-----------|---------|------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited Ed25519 implementation | Runtime |
| `typescript`, `vitest`, `esbuild`, `happy-dom`, `tsx`, `@types/node` | Build + test toolchain | Dev |

