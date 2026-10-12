#!/usr/bin/env bash
set -euo pipefail

# Verify a signed macOS release zip with the app's own update check (CI only,
# macOS). Usage: bash scripts/verify-macos.sh <zip> <tag> [<requirement>]
#
# Runs `rhg-authenticator --verify-update-zip` from the bundle inside <zip>, so
# the exact install-time path (pre-scan, extract, pinned code-signing
# requirement, sealed version == <tag>, executable main binary) is exercised
# against the exact zip that will be published. <requirement> overrides the
# app's PinnedRequirement (the dry-run job's throwaway certificate); the
# release job omits it. Shared by verify-macos and sign-macos-dryrun so the two
# cannot drift apart. Never run it in a job that received the signing key.

if [[ $# -lt 2 || $# -gt 3 || -z "$1" || -z "$2" ]]; then
  printf 'usage: %s <zip> <tag> [<requirement>]\n' "$0" >&2
  exit 2
fi
ZIP="$1"
TAG="$2"

[[ -s "$ZIP" ]] || { printf 'error: %s is missing or empty\n' "$ZIP" >&2; exit 1; }
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || { printf 'error: RUNNER_TEMP is not set to a directory\n' >&2; exit 1; }

X="$RUNNER_TEMP/verify-app"
trap 'rm -rf "$X"' EXIT
rm -rf "$X"
ditto -x -k "$ZIP" "$X"
BIN="$X/RHG Authenticator.app/Contents/MacOS/rhg-authenticator"

if [[ $# -eq 3 ]]; then
  "$BIN" --verify-update-zip "$ZIP" "$TAG" --requirement "$3"
else
  "$BIN" --verify-update-zip "$ZIP" "$TAG"
fi
