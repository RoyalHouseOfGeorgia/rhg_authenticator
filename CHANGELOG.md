# Changelog

All notable changes to the RHG Authenticator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses two-component version tags (`v1.0`, `v1.1`, …).

## [v1.2] — 2026-07-22

### Added
- Two new honor titles, **"Appointment"** and **"Other"**, in the Sign
  dropdown. The required Detail field records the specifics.
- **"Login to GitHub" button on the History tab** — sign in to GitHub without
  switching tabs; the button reflects live login state.

### Fixed
- **Card resets on repeat signs** — the PIN is now resolved before the YubiKey
  connection is opened, so signing a second (uncached) credential no longer
  forces a hardware reset mid-flow.
- **YubiKey error handling** — improved PIN handling and smart-card "card
  reset" error classification, so transient card errors are reported
  accurately instead of as generic failures.

### Security
- Closed a **PIN-cache lockout vector** and removed a stale test-vector
  generator.
- **Verify page**: revoked credentials now render with the correct red / ✗
  styling; registry and revocation fetches use `no-store` to bypass the browser
  HTTP cache; the "revocation status unknown" note is now styled.
- **Canonical key-sort parity lock** — verify-side JSON key ordering now sorts
  by Unicode code point (matching the Go signer's UTF-8 byte order), with
  regression tests covering astral-plane characters.
- Hardened CI and edge/security headers following a security audit.
- **Go toolchain security bumps** — Go 1.25.9 and 1.25.12 to pick up stdlib
  CVE fixes, including the crypto/tls ECH vulnerability (GO-2026-5856).

### Registry
- Revoked credentials `6090e8939ac35967` and `934f77b628613c35`.
- Updated the registry at the request of HRH Prince Davit.

### Changed
- Build-check contexts pinned to the matrix suffix for stable ruleset gating
  (fixes the merge-gate mismatch on macOS runner bumps).
- Added a 30-minute build-job timeout so a stalled runner fails fast.
- Added a CI `gofmt` gate; migrated CI to Node 22 LTS / Node 24.
- Numerous dependency updates via Dependabot (Fyne 2.8.0, golang.org/x/text,
  golang.org/x/image, and dev-tooling bumps).

## [v1.1] — 2026-04-03

### Registry
- Revoked credentials `cbbf6180437e4061` and `ed398a747a7237c3`.
- Registry update.

### Changed
- Dependency bumps (esbuild, actions/setup-go).

## [v1.0] — 2026-03-30

First production release of the cryptographic credential system for issuing and
verifying Royal honors.

### Signing App (Desktop)
- Self-contained Go binary with a five-tab Fyne GUI — Sign, History, Registry,
  Audit, YubiKey. Ed25519 signatures via YubiKey PIV (slot 9c, firmware 5.7+).
  Runs on macOS and Windows with no external dependencies.
- Issue credentials by filling four fields and touching the YubiKey.
- QR code output in SVG (print) and PNG (preview).
- Searchable history with per-credential revocation via GitHub PR.
- Key registry management with YubiKey/certificate import.
- Registry audit log sourced from GitHub commit history.

### Verification (Web)
- Public GitHub Pages site at verify.royalhouseofgeorgia.ge — anyone scans a
  diploma QR code and gets an instant cryptographic verification result, no app,
  account, or fee.
- Four outcomes: Verified, Invalid, Revoked, No Credential.
- Privacy-preserving revocation (only opaque SHA-256 hashes published).
- No cookies, no analytics, no tracking.
- Full proof embedded in the QR URL — works even if the site is offline.

### Verification Library (TypeScript)
- Core crypto and credential validation as a standalone TypeScript library.

### Security
- Hardware-bound private keys (YubiKey PIV, non-exportable).
- Ed25519 signatures via the audited `@noble/curves` implementation.
- Public key registry with permanent history and a tamper-visible Git audit
  trail.
- SLSA build provenance attestations and `SHA256SUMS.txt` on all release
  binaries.

[v1.2]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.1...v1.2
[v1.1]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.0...v1.1
[v1.0]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.0
