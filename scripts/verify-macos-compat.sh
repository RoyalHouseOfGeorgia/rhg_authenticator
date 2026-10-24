#!/usr/bin/env bash
set -euo pipefail

# Check that installed releases' updaters accept a signed macOS zip (CI only,
# macOS). Usage: bash scripts/verify-macos-compat.sh <zip> <tag> [<requirement>]
#
# For each old release below, downloads its published darwin-arm64 zip, checks
# it against the pinned SHA-256 BEFORE unpacking or running anything, and runs
# that OLD app's `rhg-authenticator --verify-update-zip <zip> <tag>` on <zip>.
# Passing proves users on those releases can update to <zip> in-app.
# <requirement> overrides the old app's pinned code-signing requirement (the
# dry-run job's throwaway certificate); omit it to check against the real
# pinned certificate. Run by sign-macos-dryrun (dry-run requirement, tag
# v0.0.0). Never run it in a job that received the signing key.
#
# The list is fixed: add a release when its updater should be covered, with
# its asset's SHA-256 as GitHub recorded it:
#   gh release view vX.Y.Z --json assets \
#     --jq '.assets[] | select(.name == "rhg-authenticator-darwin-arm64.zip") | .digest | ltrimstr("sha256:")'
OLD_RELEASES="
v1.5.0 a4d3426f9183d473ad2d15b49db6738898276c6603f3ccec7bcf783e3d6c37a6
v1.5.1 4c27d78fb18847623adc68ae9659355f87b652cacb0e37df3eb663ecda234cc6
v1.5.2 36a1cb3a3d1c0bf74f9db5c9a20bc734e9f46cfc86b18d96d613ef0c7c828692
"
ASSET="rhg-authenticator-darwin-arm64.zip"
RELEASES_URL="https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/download"

if [[ $# -lt 2 || $# -gt 3 || -z "$1" || -z "$2" ]]; then
  printf 'usage: %s <zip> <tag> [<requirement>]\n' "$0" >&2
  exit 2
fi
ZIP="$1"
TAG="$2"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ -s "$ZIP" ]] || die "$ZIP is missing or empty"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is not set to a directory"

X="$RUNNER_TEMP/verify-compat"
trap 'rm -rf "$X"' EXIT
rm -rf "$X"
mkdir "$X"

while read -r ver digest; do
  [[ -n "$ver" ]] || continue
  dl="$X/$ver/download"
  app="$X/$ver/app"
  mkdir -p "$dl" "$app"

  # Every error is retried: the digest check below rejects a bad body.
  curl -fsSL --retry 3 --retry-all-errors -o "$dl/$ASSET" "$RELEASES_URL/$ver/$ASSET" ||
    die "$ver: downloading $ASSET failed"
  sum="$(shasum -a 256 "$dl/$ASSET")" || die "$ver: shasum failed"
  sum="${sum%% *}"
  [[ "$sum" == "$digest" ]] || die "$ver: $ASSET SHA-256 is $sum, want $digest"

  ditto -x -k "$dl/$ASSET" "$app" || die "$ver: unpacking $ASSET failed"
  bin="$app/RHG Authenticator.app/Contents/MacOS/rhg-authenticator"
  [[ -x "$bin" ]] || die "$ver: $bin not found"

  printf '== %s updater: --verify-update-zip %s %s\n' "$ver" "$ZIP" "$TAG"
  # </dev/null: the loop reads the release list from stdin.
  if [[ $# -eq 3 ]]; then
    "$bin" --verify-update-zip "$ZIP" "$TAG" --requirement "$3" </dev/null || die "$ver updater rejects $ZIP"
  else
    "$bin" --verify-update-zip "$ZIP" "$TAG" </dev/null || die "$ver updater rejects $ZIP"
  fi
  printf 'ok: %s updater accepts %s\n' "$ver" "$ZIP"
done <<< "$OLD_RELEASES"
printf 'all old updaters accept %s\n' "$ZIP"
