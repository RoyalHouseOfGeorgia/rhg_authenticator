#!/usr/bin/env bash
set -euo pipefail

# Check a release's asset directory before it is published (CI: the release
# job on tags, release-dryrun on every other build).
# Usage: bash scripts/check-release-assets.sh <dir>
#
# Passes only if <dir> holds exactly the two app files, each non-empty:
#   rhg-authenticator-darwin-arm64.zip   (the signed Mac app)
#   rhg-authenticator-windows-amd64.exe  (the Windows app)
# Anything else in <dir> (a file, a directory, a dotfile) fails it, so a
# renamed, missing or stray artifact cannot reach the release, its
# SHA256SUMS or its provenance attestation.

EXPECTED=(
  rhg-authenticator-darwin-arm64.zip
  rhg-authenticator-windows-amd64.exe
)

if [[ $# -ne 1 || -z "$1" ]]; then
  printf 'usage: %s <dir>\n' "$0" >&2
  exit 2
fi
DIR="$1"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
failed=0
fail() { printf 'error: %s\n' "$*" >&2; failed=1; }

[[ -d "$DIR" ]] || die "$DIR is not a directory"

for name in "${EXPECTED[@]}"; do
  path="$DIR/$name"
  if [[ ! -e "$path" ]]; then
    fail "missing $path"
  elif [[ ! -f "$path" || -L "$path" ]]; then
    fail "$path is not a regular file"
  elif [[ ! -s "$path" ]]; then
    fail "$path is empty"
  fi
done

shopt -s nullglob dotglob
for path in "$DIR"/*; do
  name="${path##*/}"
  known=0
  for e in "${EXPECTED[@]}"; do
    [[ "$name" == "$e" ]] && known=1
  done
  [[ $known -eq 1 ]] || fail "unexpected entry $path"
done

[[ $failed -eq 0 ]] || die "$DIR must hold exactly: ${EXPECTED[*]}"
printf 'release assets OK: %s\n' "${EXPECTED[*]}"
