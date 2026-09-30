# Changelog

All notable changes to the RHG Authenticator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses `vMAJOR.MINOR` version tags (`v1.0`, `v1.1`, …), adding a
patch component for fix-only releases (`v1.3.1`).

## [Unreleased]

### Added
- **Error log in every build.** The app keeps an error log in release builds
  too, not just in debug builds. Entries older than 30 days are removed at
  startup.
- **Export Error Log.** **Help → Export Error Log…** saves the log to the
  Desktop so it can be emailed. The Revocation Failed and Submission Failed
  dialogs have the same button.

### Changed
- **Reconnect after starting offline.** If GitHub couldn't be reached at
  startup, the Registry tab's button reads **Offline — Reconnect** and retries
  when clicked. Previously it only offered to log out. Submit for Review does
  the same while offline. The History tab's button now reads
  **Connect to GitHub**.

### Fixed
- **Revocation errors are explained.** A failed revocation now shows why (for
  example a rate limit or a permission problem) instead of "failed to submit
  revocation". An expired GitHub session asks you to log in again.
- **Fatal-error reports no longer include the log tail.** They are posted to
  the public tracker without a preview.

## [v1.4] — 2026-09-30

### Added
- **Honor-restricted keys.** A registry key can carry `allowed_honors`, a list
  of honor titles it may sign. The verification page rejects a credential
  signed by that key whose honor is not in the list. Keys without the field
  are unrestricted.

### Changed
- **Backdated honors verify.** A key's `from` date no longer limits
  verification — only its `to` date does.
- **New registry fields no longer break the app.** The app ignores registry
  fields it doesn't recognise and keeps them when the Registry tab saves.
  Earlier versions show the registry as offline once a new field appears
  (signing still works) — update to this version.
- The verification site is served uncached, and registry changes are now
  checked by CI.

### Fixed
- **QR codes save to the Desktop again.** Save SVG / Save PNG now open on the
  Desktop, like Export Issuance Log. On a Mac, the first save asks for access to
  the Desktop folder — click **Allow**. If a save fails, the error points to
  System Settings → Privacy & Security → Files and Folders, where the app needs
  Desktop access (the Mac app is a new app to macOS since v1.3.1).

### Registry
- New key for H.H. Tavadi Kimon Andreou, PhD (Chief Administrator and Vice
  Chancellor), restricted to Appointment.

## [v1.3.1] — 2026-09-29

### Changed
- **Mac download is now a double-clickable app.** Releases ship
  `rhg-authenticator-darwin-arm64.zip` containing **RHG Authenticator.app**
  (with name, icon and version) instead of a bare command-line binary, which
  is no longer published. Apple Silicon only. The app is not signed with an
  Apple Developer ID, so the first launch of each downloaded version needs
  **Open Anyway** in System Settings → Privacy & Security — see
  [Download & install](README.md#download--install).

### Fixed
- **Update notifications never appeared.** The update check only understood
  three-part versions (`v1.2.3`), but releases are tagged `v1.2`, `v1.3`, so
  it silently reported "no update" for every release. It now accepts `v1.3`
  and `v1.3.1`. Copies of v1.3 or earlier still carry the old check and won't
  be told about this release — install it manually.

## [v1.3] — 2026-09-25

### Added
- **Bulk Sign from File…** on the Sign tab: sign every row of a CSV
  (`name,honor,detail,date`) in one session with a single PIN entry. Invalid
  rows are skipped and listed before signing, each with the reason (an
  unrecognized honor lists the allowed titles); rows already in the issuance log
  are not signed again, so a stopped batch can be resumed by re-opening the
  same file. The summary reports rows processed and successful, and a results
  CSV (`name,honor,detail,date,url,status,error`) can be exported with each
  row's verification URL.
- **`scripts/rebuild_urls.py`**: rebuild verification URLs without a YubiKey
  from a payload + signature, a signer's issuance log (`issuances.json`), or a
  CSV of payloads and signatures. File input produces a
  `name,honor,detail,date,url` CSV. Standard-library Python only; entries are
  checked structurally (log entries against their stored hash), signatures are
  not verified.
- **Python CI workflow** (`python.yml`): runs the script's tests and gitleaks.
  Changes that touch only `scripts/*.py` no longer run the Go/TypeScript build
  pipeline. CodeQL for Python (`codeql-python.yml`) runs on every PR so the
  CodeQL PR check can compare alerts against `main`.
- **Export Issuance Log…** on the History tab: saves a copy of the issuance
  log (`rhg-issuances-YYYY-MM-DD.json`) through a save dialog that opens on the
  Desktop, then confirms where the file went — no need to find the app's data
  folder. The exported file is the input for `scripts/rebuild_urls.py`.

### Fixed
- **Save failures were silent.** When the save dialog couldn't write to the
  chosen location (for example, macOS denied access to the Desktop), Save SVG,
  Save PNG and Export Results CSV did nothing. They now show an error.

### Security
- **Secret scanning was detecting nothing.** `.gitleaks.toml` had an
  `[extend]` table without `useDefault = true`, which loads zero rules, so
  both the CI gitleaks job and local runs passed regardless of content. The
  default rules are now enabled, with allowlist entries for the verified
  false positives (public keys, test vectors, the public OAuth client ID, a
  fake test token). The `.githooks/pre-commit` hook now runs gitleaks on
  staged changes when it is installed, blocking a secret before it is
  committed rather than after it is pushed.
- **Go toolchain bumped to 1.27.1.** Go 1.25 left the two-release support
  window when 1.27 shipped, so `go1.25.14` is its final patch and no further
  stdlib security fixes will land for it. The build now uses a supported
  toolchain, and the documented minimum for building from source is Go 1.26.
  (Before the move, Go 1.25.14 picked up the GO-2026-5026 and GO-2026-5972
  stdlib fixes.)

### Changed
- **Verify page crypto library** — `@noble/curves` upgraded from 1.9.7 to
  2.4.0 (major version); the verification bundle and its SRI hash were rebuilt.
- The SRI update script now fails loudly instead of silently writing nothing,
  and CI uses it as the SRI check.
- Numerous dependency updates via Dependabot (Fyne 2.8.1, golang.org/x/text
  0.42, vitest 5, GitHub Actions, and dev-tooling bumps).

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

[Unreleased]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.4...HEAD
[v1.4]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.3.1...v1.4
[v1.3.1]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.3...v1.3.1
[v1.3]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.2...v1.3
[v1.2]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.1...v1.2
[v1.1]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/compare/v1.0...v1.1
[v1.0]: https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.0
