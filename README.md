<p align="center">
  <img src="verify/royal-arms-120.png" alt="Royal Arms of Georgia" width="120" height="120">
</p>

<h1 align="center">Royal House of Georgia — Digital Honor Authenticator</h1>

<p align="center">
  Cryptographically verifiable credential system for the Royal House of Georgia.<br>
  Ed25519 signatures via YubiKey, QR codes on physical diplomas, credential revocation, public verification via GitHub Pages.
</p>

<p align="center">
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/RoyalHouseOfGeorgia/rhg_authenticator/build.yml?branch=main&amp;label=Build%20%26%20Test" alt="Build &amp; Test"></a>
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/actions/workflows/govulncheck.yml"><img src="https://img.shields.io/github/actions/workflow/status/RoyalHouseOfGeorgia/rhg_authenticator/govulncheck.yml?branch=main&amp;label=govulncheck" alt="govulncheck"></a>
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/actions/workflows/deploy-pages.yml"><img src="https://img.shields.io/github/actions/workflow/status/RoyalHouseOfGeorgia/rhg_authenticator/deploy-pages.yml?branch=main&amp;label=Pages" alt="Pages"></a>
  <br>
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases"><img src="https://img.shields.io/github/v/release/RoyalHouseOfGeorgia/rhg_authenticator" alt="Latest release"></a>
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases"><img src="https://img.shields.io/github/release-date/RoyalHouseOfGeorgia/rhg_authenticator" alt="Release date"></a>
  <a href="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases"><img src="https://img.shields.io/github/downloads/RoyalHouseOfGeorgia/rhg_authenticator/total" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-proprietary-lightgrey" alt="License: proprietary"></a>
  <br>
  <a href="#download--install"><img src="https://img.shields.io/badge/macOS-14%2B%20%7C%20Apple%20silicon-000000?logo=apple" alt="macOS 14+, Apple silicon"></a>
  <a href="#download--install"><img src="https://img.shields.io/badge/Windows-10%2F11%20%7C%20x64-0078D4?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHJlY3QgeD0iMSIgeT0iMSIgd2lkdGg9IjEwLjUiIGhlaWdodD0iMTAuNSIvPjxyZWN0IHg9IjEyLjUiIHk9IjEiIHdpZHRoPSIxMC41IiBoZWlnaHQ9IjEwLjUiLz48cmVjdCB4PSIxIiB5PSIxMi41IiB3aWR0aD0iMTAuNSIgaGVpZ2h0PSIxMC41Ii8%2BPHJlY3QgeD0iMTIuNSIgeT0iMTIuNSIgd2lkdGg9IjEwLjUiIGhlaWdodD0iMTAuNSIvPjwvc3ZnPg%3D%3D" alt="Windows 10/11, x64"></a>
  <a href="go/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/RoyalHouseOfGeorgia/rhg_authenticator?filename=go%2Fgo.mod&amp;logo=go" alt="Go version"></a>
  <a href="macos/README.md"><img src="https://img.shields.io/badge/Swift-6-F05138?logo=swift&amp;logoColor=white" alt="Swift 6"></a>
  <a href="windows/README.md"><img src="https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&amp;logoColor=white" alt=".NET 10"></a>
  <a href="DEVELOPER.md"><img src="https://img.shields.io/badge/TypeScript-7-3178C6?logo=typescript&amp;logoColor=white" alt="TypeScript 7"></a>
  <a href="ARCHITECTURE.md"><img src="https://img.shields.io/badge/signing-Ed25519%20%2B%20YubiKey-84BD00?logo=yubico&amp;logoColor=white" alt="Signing: Ed25519 + YubiKey"></a>
  <br><br>
  <a href="https://verify.royalhouseofgeorgia.ge"><img src="https://img.shields.io/badge/Verify%20a%20credential-8B0000?style=for-the-badge" alt="Verify a credential"></a>
</p>

---

## Contents

- [How It Works](#how-it-works) · [Components](#components)
- [Download & install](#download--install) — Mac and Windows
- [Using the app](#using-the-app) — [Sign](#sign-tab), [History](#history-tab), [Registry](#registry-tab), [Audit](#audit-tab), [YubiKey](#yubikey-tab), [Keyboard shortcuts](#keyboard-shortcuts), [Troubleshooting](#troubleshooting)
- [Build from source](#build-from-source) · [Documentation](#documentation) · [Binary Integrity](#binary-integrity) · [Dependencies](#dependencies)

## How It Works

1. **Issuance**: The operator opens the RHG Authenticator desktop app, fills in the credential form, and signs with a YubiKey
2. **Encoding**: The signed credential is encoded into a QR code (saved as SVG for print or high-resolution PNG; PNG preview in the app)
3. **Verification**: Anyone scans the QR code, opening a public page that checks the signature against a key registry

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **Mac app** | Swift (SwiftUI) | Native app in `macos/` — 5 tabs: Sign, History, Registry, Audit, YubiKey; updates itself |
| **Windows app** | C# (.NET 10, WPF) | Native app in `windows/` — the same 5 tabs plus Help; a single `.exe` |
| **Go core** | Go (C library) | All signing, YubiKey, registry, history, GitHub and update logic, built as a C library (`go/cmd/rhgcore`) that both apps call |
| **Verification library** | TypeScript | Core crypto, credential validation, key registry, revocation list |
| **Verification page** | TypeScript | Public GitHub Pages site for QR code verification |
| **Python tools** | Python | `scripts/rebuild_urls.py` (rebuild verification URLs from existing signatures, no YubiKey), `scripts/rhg_qr.py` (QR image from a URL), `scripts/rhg_revocation_hash.py` (revocation hash for a URL) |

1176 tests passing (824 Go + 318 TypeScript + 34 Python) — the Go core, the TypeScript verifier and the Python tools; the Swift and .NET suites of the two apps run in CI too.

## Download & install

Download the app from the [latest release](https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/latest).

**Requirements:**
- **Mac:** macOS 14 (Sonoma) or later on an Apple silicon Mac (Apple menu → **About This Mac** → **Chip** says "Apple M…"). There is no Intel build; on an Intel Mac the app won't open.
- **Windows:** Windows 10 or 11, 64-bit (x64).
- A YubiKey whose signing key is in the key registry (see [YubiKey setup](go/README.md#yubikey-setup)), and an internet connection when the app starts.

### Mac

1. Download **`rhg-authenticator-darwin-arm64.zip`**.
2. Open your **Downloads** folder. If you see a `.zip`, double-click it (Safari usually unzips it for you).
3. Drag **RHG Authenticator** into your **Applications** folder, then double-click it.
4. macOS says it can't verify the app. Click **Done**.
5. Right away, open **System Settings** → **Privacy & Security**, scroll down to "RHG Authenticator was blocked…", and click **Open Anyway**.
6. In the box that pops up, click **Open Anyway** again, then enter your Mac password (or use Touch ID).

If the **Open Anyway** button isn't there, double-click the app again, then go back to System Settings.

After this, the app opens normally. (The app is signed with the project's own certificate, not one from Apple, which is why macOS asks.)

If macOS asks whether RHG Authenticator can access your Desktop folder the first time you save a QR code, click **Allow**.

**Updates install automatically** as long as the app is in your **Applications** folder:
- When a new version has downloaded, a banner at the top of the app says "Version … is ready to install." Click **Restart Now**, or just keep working — it installs the next time you quit the app.
- You won't need to click **Open Anyway** or allow Desktop access again.
- If the banner shows a **Download** link instead, the app isn't in Applications or the update couldn't be installed: move the app into Applications (the banner says so when that is the reason), or download the new version and install it by hand.

**Upgrading from version 1.5.0 or later:** nothing to do — the app updates itself to this version like any other update.

**Upgrading from a version before 1.5.0:** install it by hand one last time — quit the app, drag the new one into Applications, choose **Replace**, then repeat steps 4–6 above. After that, every version installs itself.

### Windows

1. Download **`rhg-authenticator-windows-amd64.exe`**. It is the whole app — there is nothing to install.
2. Your browser may block the download because it "isn't commonly downloaded". In Microsoft Edge: open the **Downloads** list, point at the file, click **…** → **Keep**, then **Show more** → **Keep anyway**.
3. Double-click the file. If Windows shows "Windows protected your PC", click **More info** → **Run anyway**.

If there is no **Run anyway** button, Smart App Control is turned on and blocks the app — contact the maintainer.

You can move the `.exe` anywhere you like (for example your Desktop) and pin it to the taskbar.

**Updating:** Windows doesn't update the app by itself. When a new version is out, a banner at the top of the app says "Version … is available —" with a **Download** link. Download the new `.exe` (steps 1–3), quit the app, delete the old `.exe` and put the new one in its place (re-pin it if you had pinned the old one). Your history and settings live in `%APPDATA%\rhg-authenticator` and are kept.

Only one copy of the app runs at a time: opening it again brings the open window (or its open dialog) to the front.

## Using the app

The app has five tabs: **Sign**, **History**, **Registry**, **Audit** and **YubiKey**. On Windows a sixth tab, **Help**, holds **Export Error Log…**. On a Mac the menu bar has:
- **File** — Bulk Sign from File…, Save QR Code as SVG… and as PNG…, Export Issuance Log…
- **Edit** — Find…
- **View** — the tabs and Refresh
- **Help** — this guide, Export Error Log…

Dates are shown as YYYY-Mon-DD (e.g. 2026-Mar-15).

### Before you start: internet and GitHub

- **The key registry is downloaded only when the app starts.** If that fails — no internet, or the site is down — nothing new can be signed until you restart the app. Signing says: "Signing is unavailable: the key registry could not be downloaded. Check your internet connection and restart RHG Authenticator." A credential that was already issued is still shown.
- **GitHub login** is needed only to **Revoke** and to **Submit for Review**. The login button is on the History and Registry tabs: **Login to GitHub** (Windows) or **Log In to GitHub…** (Mac). It shows a code to enter at GitHub in your browser. Once logged in, the button shows your GitHub name. To log out, click it (on a Mac, choose **Log Out…** from its menu) and confirm. Your login is kept in the Mac Keychain / Windows Credential Manager.
- If GitHub couldn't be reached, the button reads **Offline — Reconnect**. Clicking it restores the GitHub login only — it doesn't make signing available again if the registry didn't download; for that, restart the app.

### Sign tab

1. Fill in **Recipient** (full name), **Honor** (pick from the list), **Detail** (the specific distinction or rank) and **Date** (defaults to today, UTC).
2. Plug in your YubiKey and click **Sign Credential**.
3. Enter your YubiKey PIN. Tick **Remember PIN for this session** to skip the PIN for the next 5 minutes (it is kept in locked memory and cleared after 5 minutes).
4. The QR code appears. Click **Save SVG** (vector, for print) or **Save PNG** (2048 px); on a Mac they read **Save SVG…** and **Save PNG…**. Click **Copy URL** to copy the verification link.

Before asking for the PIN, the app refuses to sign if the credential would not verify: the YubiKey's key is not in the registry, the key is not valid on the credential date, or the key may not sign that honor. The message starts "This YubiKey's key …" and says which.

If the same credential (identical recipient, honor, detail and date) is already in the issuance log, the app skips the PIN, shows the original QR code and says the credential was previously generated (on Windows in an **Already Issued** message) — no new record is created. If the issuance log can't be read, signing is blocked until it can (see [Troubleshooting](#troubleshooting)).

The verification URL must fit a printable QR code (625 characters), which leaves room for roughly 220–290 Latin or 75–95 Georgian letters for recipient and detail combined (the longer the honor title, the less room). A credential that is too long is refused before the PIN prompt and the message says how much to shorten.

If signing fails, the status area shows what went wrong and a **Report Issue** button, which files a GitHub issue (if you are logged in) or opens a pre-filled form in your browser. The issue contains the message shown and the kind of hardware error — never the error log. There is no Report Issue button for an input problem or a wrong PIN.

#### Bulk Sign

Sign many credentials in one session from a CSV file.

1. Prepare a CSV with a header row containing `name`, `honor`, `detail`, `date` (any order, any letter case; extra columns are ignored):
   ```csv
   name,honor,detail,date
   Jane Doe,Order of the Crown of Georgia,Knight Commander,2026-09-24
   ```
   - **honor** must be one of these titles, copied exactly (spelling, punctuation and capitalisation matter):
     - `Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ`
     - `Order of the St. Queen Tamar of Georgia`
     - `Order of the Crown of Georgia`
     - `Medal of Merit of the Royal House of Georgia`
     - `Ennoblement`
     - `Appointment`
     - `Other`
   - **date** must be `YYYY-MM-DD`
   - Limits: 500 rows, 2 MB
2. Plug in your YubiKey and choose **Bulk Sign from File…** (Sign tab; on a Mac also the File menu).
3. Review the confirmation: row counts, the first few names to be signed, and any invalid rows (with line numbers) that will be skipped.
4. Click **Sign** and enter your PIN once for the whole batch. If your key requires touch, touch it when it blinks for each row.
5. When the batch ends, the summary shows what happened. Click **Export Results CSV…** to save `name,honor,detail,date,url,status,error` for every row — `url` is the verification URL.

| Status | Meaning |
|---|---|
| `signed` | Signed in this run |
| `already_issued` | Already in the issuance log — not signed again; URL rebuilt from the logged signature |
| `invalid` | Skipped: failed validation, or duplicates an earlier row in the same file |
| `failed` | Either this YubiKey's key can't sign this row (not in the registry, not valid on its date, or not allowed that honor — the error says which; checked before the PIN, and the batch goes on without it), or a signing error on this row stopped the batch |
| `not_attempted` | The batch was cancelled or stopped before this row |

A wrong PIN, a YubiKey error, or a failure to write the issuance log stops the batch; rows signed before the stop stay signed and logged. If the log write failed, that row shows `signed` with an error: it was signed but not logged, so opening the file again signs it again (same QR code). **Cancel** stops after the current row. To finish, open the same file again: rows already signed are reported as `already_issued`, so only the rest are signed.

**Excel tips:** use *Save As → CSV UTF-8* (plain "CSV" turns Georgian text into `????`, and such rows are rejected); format the date column as Text so Excel doesn't rewrite it; keep each cell on one line; if your Excel saves with `;` separators, change the list separator to `,`.

### History tab

Every credential signed on this computer, newest first. Search by recipient; select one to see its details.

- **Revoke** — revokes the selected credential: the app opens a pull request that adds it to the public revocation list; once the maintainer merges it, the verification page shows the credential as revoked. Needs a GitHub login with **Write (collaborator) access** to this repository; without it the app says to ask the maintainer to add you as a collaborator. If the credential is already revoked, or a revocation for it is already waiting, no new request is made and the app says so. If the revocation list couldn't be loaded, **Revocation unavailable** shows next to the buttons; click **Refresh** to try again.
- **Delete Entry…** — see [Deleting an entry](#deleting-an-entry).
- **Export Issuance Log…** — saves a copy of the log as `rhg-issuances-YYYY-MM-DD.json` (for example to email to the maintainer). It holds every recipient's details.
- **Remove Duplicates…** — removes extra records of a credential that was signed more than once, keeping the earliest. A backup of the log is saved first (named like the Delete Entry backup below). The removed records were the same credential, so any QR code already printed from them still verifies.

#### Deleting an entry

**Delete Entry…** (or the Delete key in the list) removes the selected record from this computer's issuance log. It asks first; unless the credential is already revoked, the question offers **Revoke Instead**. On Windows the safe choice, **Cancel**, is the default.

Before deleting, the app saves a backup of the whole log next to it, named `issuances.json.bak-<date and time in UTC>` — for example `issuances.json.bak-20261027T120000Z` (if that name is taken, `-2`, `-3`, … is added). A backup is never overwritten. Only the selected record is deleted; other records of the same credential stay.

**What deleting does not do:**
- **The credential stays valid.** Anyone with its QR code can still verify it.
- **It can no longer be revoked from the app**, because History no longer has its record. To revoke it later, sign exactly the same credential again (that brings the record back; it needs the registry to have downloaded and a key allowed to sign that credential), then click **Revoke** — or ask the maintainer.
- **Signing the same credential again** with the same YubiKey creates a new record with the identical QR code, without the "previously generated" notice.

To undo a deletion, restore the backup.

#### Restoring the log from a backup

1. Quit the app (on a Mac, **⌘Q** or close its window).
2. Open the app's data folder:
   - **Mac:** in Finder choose **Go** → **Go to Folder…** (⇧⌘G), paste `~/Library/Application Support/rhg-authenticator` and press Return.
   - **Windows:** paste `%APPDATA%\rhg-authenticator` into the File Explorer address bar and press Enter.
3. Rename the current `issuances.json` to something else (for example `issuances-old.json`). Don't delete it.
4. Copy the backup you want (`issuances.json.bak-…`) and rename the copy to `issuances.json`. On a Mac, if Finder asks about changing the extension, choose **Use .json**; on Windows, if Explorer warns about changing the extension, choose **Yes**.
5. Start the app.

Records signed after that backup was made no longer appear in History; they have the same [consequences as a deleted entry](#deleting-an-entry).

### Registry tab

Manages the key registry — the public list of YubiKey keys that may sign credentials. It is loaded when the app starts (from GitHub when you are logged in, otherwise from the verification site, which can lag GitHub by 10–15 minutes).

- **Fetch from Server** — reloads the registry. If you have unsubmitted edits, it asks before discarding them.
- **Add Entry** / **Edit Entry** (on a Mac **Add Entry…** / **Edit Entry…**; to edit, you can also double-click a row or press Enter, Mac: Return) — the form fills in the key with **Import Certificate** (on a Mac **Import Certificate…**; a `.crt`/`.pem` file) or **Import from YubiKey**. Entries cannot be deleted — revoke a key by setting its expiry date (which may be earlier than its From date).
- **Submit for Review** — opens a pull request with your changes for the maintainer to review (needs a GitHub login with Write access). If the registry on GitHub changed since you loaded it, it is refused: click **Fetch from Server**, redo your edits and submit again.
- The **Restrictions** column shows which honors a key may sign ("(none)" means any; "(invalid)" means the verification page would reject the value). It is read-only here.
- On a Mac, **⌘C** or right-click → **Copy** copies the selected row; on Windows, point at a cell to see its full text.

If you quit with unsubmitted changes, the app asks first.

### Audit tab

The change history of the registry file on GitHub, so any change to the registry can be checked. **Refresh** reloads it; **Open on GitHub** (or double-click / Enter) opens the selected change in your browser.

### YubiKey tab

**Check YubiKey** reads the inserted YubiKey (no PIN needed) and says whether its key is in the registry and which honors it may sign. If the registry didn't download at start-up, it says the registry is unavailable.

### Error log and updates

- **Export Error Log…** (Mac: **Help** menu; Windows: **Help** tab, which works even while the app is starting) saves the app's diagnostic log as `rhg-error-log-YYYY-MM-DD.log` to attach to an email. The Revocation Failed, Delete Failed, Remove Duplicates Failed and Submission Failed messages also offer it. The log may include your GitHub username and file paths, but never PINs or keys. Entries older than 30 days are removed automatically. The file itself is `debug.log` in the data folder (`~/Library/Application Support/rhg-authenticator` on a Mac, `%APPDATA%\rhg-authenticator` on Windows).
- **Update banner:** the app checks for a new version at start-up and every 6 hours. On a Mac it shows "Version … is ready to install." with **Restart Now** (see [Mac](#mac)), and after updating "Updated to version …" with **What's New**. On Windows it shows "Version … is available —" with **Download** (see [Windows](#windows)).

### Keyboard shortcuts

| Action | Windows | Mac |
|---|---|---|
| Switch tabs | — | ⌘1 – ⌘5 |
| Refresh the History, Registry or Audit tab | F5 | ⌘R |
| Search History | Ctrl+F (on the History tab) | ⌘F (from any tab; opens History) |
| Delete the selected History entry | Del | Delete |
| Open the selected Audit change / edit the selected Registry entry | Enter or double-click | Return or double-click |
| Copy the selected Registry row | — | ⌘C |
| Confirm / cancel a dialog | Enter / Esc | Return / Esc |
| Destructive confirmations (Delete, discard registry edits…) | default to **Cancel** | have no default button: Return does nothing, Esc cancels |

### Troubleshooting

To send the maintainer details of a problem, use **Export Error Log…** (see [Error log and updates](#error-log-and-updates)).

#### Common errors

| Message | Cause | Fix |
|---------|-------|-----|
| **YubiKey not detected** | No YubiKey visible to the smart card service | Unplug and replug the key. Check that CCID is enabled: `ykman config usb` |
| **Smart card service not available** | The system's smart card service isn't running | Mac: built in, should always work. Windows: make sure the "Smart Card" service is running (`services.msc`) |
| **No signing certificate found on YubiKey (PIV slot 9c)** | Slot 9c has no certificate, or not an Ed25519 one | Follow [YubiKey setup](go/README.md#yubikey-setup). Ed25519 needs firmware 5.7 or later — check with `ykman info` |
| **This YubiKey's key is not in the registry …** / **… is valid only until …** / **… may not sign this honor …** | The key can't sign a credential that would verify | Use a registered YubiKey, or ask the maintainer to update the registry |
| **Signing is unavailable: the key registry could not be downloaded …** | No internet when the app started | Check your connection and restart the app |
| **Could not read the issuance log, so duplicates can't be checked** | `issuances.json` in the data folder is damaged | [Restore it from a backup](#restoring-the-log-from-a-backup) (the newest `issuances.json.bak-…`) or from an exported copy |
| **Too long to fit in a QR code by about N letters …** | Recipient + detail don't fit a printable QR code | Shorten the detail (or recipient) by at least the amount shown. Nothing was signed or logged |
| **Invalid credential data: …** | A field breaks a rule (e.g. detail over 2000 characters, control characters) | Fix the field named in the message and sign again |
| **Your GitHub account can't submit changes to this repository** | Your GitHub account isn't a collaborator with Write access | Ask the maintainer to add you as a collaborator, accept the e-mailed invitation, then try again |
| **Signing failed** / **Failed to read YubiKey** | An unexpected error | **Export Error Log…** and send the file |
| **Offline — Reconnect** on the login button; Revoke stays disabled | GitHub couldn't be reached | Click **Offline — Reconnect**. If it still can't connect, check your network and try again |
| **Version … is available — Download** stays instead of **ready to install** (Mac) | The app isn't in **Applications**, or the update couldn't be downloaded or checked | Move the app into **Applications** and reopen it; otherwise click **Download** and install by hand. The error log's `update:` lines say why |
| **You don't have permission to save there** | Mac: the app was denied access to that folder (Desktop, Documents or Downloads) | System Settings → Privacy & Security → Files and Folders → RHG Authenticator → turn on that folder, or choose another folder |

#### Checking a YubiKey

1. **Firmware**: `ykman info` — Ed25519 needs firmware 5.7 or later
2. **CCID mode**: `ykman config usb` — the CCID interface must be enabled
3. **Slot 9c**: `ykman piv info` — should show a certificate in slot 9c (SIGNATURE)
4. **In the app**: on the **YubiKey** tab click **Check YubiKey** — no PIN needed

## Build from source

- **Go core** (the C library both apps use): [go/README.md](go/README.md#building-the-core-library)
- **Mac app**: [macos/README.md](macos/README.md)
- **Windows app**: [windows/README.md](windows/README.md)

### Verification library (TypeScript)

```bash
npm install
npm test              # 318 tests
npm run lint          # tsc --noEmit
npm run build:verify  # Bundle verification page JS
```

Requires Node.js 24+.

### Rebuilding verification URLs (Python)

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

#### QR code and revocation hash

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
- **README.md** (this file) — Install the apps and use them
- **[go/README.md](go/README.md)** — Go core: package layout, building the C library, YubiKey setup
- **[macos/README.md](macos/README.md)** — Mac app: layout, build and test
- **[windows/README.md](windows/README.md)** — Windows app: layout, build and test
- **[DEVELOPER.md](DEVELOPER.md)** — Developer guide: TypeScript library, CI jobs, where feature logic goes, release signing, app icon
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design, security model, data flows, how the native apps use the Go core
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

**Stronger check — build provenance** (needs the [GitHub CLI](https://cli.github.com/); replace `v2.0.0` with the release's tag and the file name with the one you downloaded):
```bash
gh attestation verify rhg-authenticator-windows-amd64.exe \
  --repo RoyalHouseOfGeorgia/rhg_authenticator \
  --signer-workflow RoyalHouseOfGeorgia/rhg_authenticator/.github/workflows/build.yml \
  --source-ref refs/tags/v2.0.0
```
This proves the file was built by the release workflow from that tag. Only the maintainer can create tags, so pinning `--source-ref` rejects provenance produced from any other branch or tag. The checksums file lives on the same release page as the download, so on its own it only detects a corrupted download.

A genuine release has a `vX.Y.Z` tag (e.g. `v2.0.0`) and is published by **github-actions[bot]** — the release page shows the author. Don't install from a release that differs; the app's own updater ignores such releases.

## Dependencies

### Go core

| Dependency | Purpose |
|-----------|---------|
| [`go-piv/piv-go/v2`](https://github.com/go-piv/piv-go) | YubiKey PIV access (Ed25519 signing over PC/SC) |
| [`skip2/go-qrcode`](https://github.com/skip2/go-qrcode) | QR code generation (SVG + PNG) |
| [`zalando/go-keyring`](https://github.com/zalando/go-keyring) | GitHub login stored in the OS keychain (macOS Keychain, Windows Credential Manager) |
| `golang.org/x/sys` | OS calls: Windows Desktop folder lookup, loading `Winscard.dll` from System32 only, macOS atomic swap and checks for in-app updates |
| `golang.org/x/text` | NFC Unicode normalization |
| Go stdlib | `crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64` |

### Windows app

| Dependency | Purpose |
|-----------|---------|
| [`CommunityToolkit.Mvvm`](https://github.com/CommunityToolkit/dotnet) | MVVM helpers (observable properties, commands) |

### Mac app

No third-party packages — SwiftUI, AppKit and Foundation only.

### TypeScript (verification library)

| Dependency | Purpose | Type |
|-----------|---------|------|
| [`@noble/curves`](https://github.com/paulmillr/noble-curves) | Audited Ed25519 implementation | Runtime |
| `typescript`, `vitest`, `esbuild`, `happy-dom`, `tsx`, `@types/node` | Build + test toolchain | Dev |
