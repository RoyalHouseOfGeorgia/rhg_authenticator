#!/usr/bin/env bash
set -euo pipefail

# Sign the macOS app bundle with the release certificate (CI only, macOS).
# Usage: P12_B64=... P12_PW=... bash scripts/sign-macos.sh <in.zip> <out.zip>
#
# <in.zip>  ditto zip of "RHG Authenticator.app" (the build job's artifact)
# <out.zip> where to write the re-signed bundle (must differ from <in.zip>)
# P12_B64   base64 PKCS#12 holding the signing key + cert (MACOS_SIGNING_P12)
# P12_PW    its password (MACOS_SIGNING_P12_PASSWORD)
#
# The key lives only in a throwaway keychain and a decoded file under
# $RUNNER_TEMP, both removed when this script exits. Verification of the result
# (rhg-authenticator --verify-update-zip) belongs in a separate JOB that never
# received the signing material: the runner keeps a job's secrets in memory for
# the whole job, so the build's binary must not run anywhere in a signing job.

APP_NAME="RHG Authenticator.app"

if [[ $# -ne 2 || -z "$1" || -z "$2" ]]; then
  printf 'usage: %s <in.zip> <out.zip>\n' "$0" >&2
  exit 2
fi
IN="$1"
OUT="$2"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ -n "${P12_B64:-}" ]] || die "P12_B64 is not set"
[[ -n "${P12_PW:-}" ]] || die "P12_PW is not set"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is not set to a directory"
[[ -f "$IN" ]] || die "$IN not found"
[[ "$IN" != "$OUT" ]] || die "<in.zip> and <out.zip> must be different paths"
[[ ! -e "$OUT" ]] || die "$OUT already exists"

# 1. Paths first, then the only cleanup. It must be idempotent: a failing
#    command in an EXIT trap would replace the script's exit status.
KC="$RUNNER_TEMP/rhg-signing.keychain-db"
KC_PW=$(openssl rand -hex 32)
KEYCHAIN_LOCK_SECS=3600 # auto-lock; far longer than this script runs
P12="$RUNNER_TEMP/rhg-signing.p12"
APPDIR="$RUNNER_TEMP/app"
trap 'security delete-keychain "$KC" 2>/dev/null || true; rm -f "$P12"; rm -rf "$APPDIR"' EXIT

# 2. Unpack the unsigned bundle.
rm -rf "$APPDIR"
ditto -x -k "$IN" "$APPDIR"
APP="$APPDIR/$APP_NAME"
[[ -d "$APP" ]] || die "$IN does not contain $APP_NAME"

# 3. Import the identity into a dedicated keychain.
printf '%s' "$P12_B64" | base64 -D > "$P12"
[[ -s "$P12" ]] || die "decoded P12_B64 is empty"
security create-keychain -p "$KC_PW" "$KC"
security set-keychain-settings -lut "$KEYCHAIN_LOCK_SECS" "$KC"
security unlock-keychain -p "$KC_PW" "$KC"
security import "$P12" -k "$KC" -P "$P12_PW" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KC_PW" "$KC" >/dev/null
# Prepend KC to the user search list (codesign resolves the cert chain through
# it). Read the existing entries line by line so a path with spaces survives.
EXISTING_LIST=$(security list-keychains -d user)
EXISTING=()
while IFS= read -r line; do
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line#\"}"
  line="${line%\"}"
  if [[ -n "$line" ]]; then EXISTING+=("$line"); fi
done <<< "$EXISTING_LIST"
security list-keychains -d user -s "$KC" ${EXISTING[@]+"${EXISTING[@]}"}
IDENTITIES=$(security find-identity -p codesigning "$KC")
printf '%s\n' "$IDENTITIES"

# 4. Sign by SHA-1 hash, not name: a name lookup can fail ("no identity found")
#    for an untrusted self-signed cert. macOS lists the same identity twice when
#    it deems it valid and once otherwise, hence sort -u.
HASHES=$(printf '%s\n' "$IDENTITIES" \
  | sed -nE 's/^ *[0-9]+\) ([0-9A-F]{40}) .*/\1/p' \
  | sort -u)
COUNT=$(printf '%s' "$HASHES" | grep -c '^' || true)
[[ "$COUNT" == "1" ]] || die "expected exactly 1 code-signing identity in the keychain, found $COUNT"
IDENTITY_SHA1="$HASHES"
codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" "$APP"

# 5. The bundle must not opt in to quarantining files it writes.
if /usr/libexec/PlistBuddy -c 'Print :LSFileQuarantineEnabled' "$APP/Contents/Info.plist" >/dev/null 2>&1; then
  die "Info.plist must not set LSFileQuarantineEnabled"
fi
# No resource forks, extended attributes or quarantine: AppleDouble ._* or
# __MACOSX entries would fail the updater's single-top-level-dir check.
mkdir -p "$(dirname "$OUT")"
ditto -c -k --norsrc --noextattr --noqtn --keepParent "$APP" "$OUT"
printf 'Signed %s -> %s with %s\n' "$IN" "$OUT" "$IDENTITY_SHA1"
