#!/usr/bin/env bash
set -euo pipefail

# Rebuild verify.js and update the SRI integrity hash in verify/index.html.
# Usage: ./scripts/update-sri.sh
#   --check   validate the current hash without modifying files (exit 1 on mismatch)

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY_JS="$SCRIPT_DIR/verify/verify.js"
INDEX_HTML="$SCRIPT_DIR/verify/index.html"

command -v openssl >/dev/null || { printf 'error: openssl is required\n' >&2; exit 1; }

# Build verify.js
npm run build:verify --prefix "$SCRIPT_DIR" >/dev/null

# Compute SHA-384
HASH=$(openssl dgst -sha384 -binary "$VERIFY_JS" | openssl base64 -A)
SRI="sha384-$HASH"

# Anchor on the verify.js script tag rather than a bare integrity attribute, so
# a second SRI-pinned resource in index.html can never be rewritten by mistake.
TAG_PATTERN='src="verify\.js" integrity="sha384-[A-Za-z0-9+/=]*"'
MATCHES=$(grep -cE "$TAG_PATTERN" "$INDEX_HTML" || true)
if [[ "$MATCHES" != "1" ]]; then
  printf 'error: expected exactly 1 verify.js integrity attribute in %s, found %s\n' \
    "$INDEX_HTML" "$MATCHES" >&2
  exit 1
fi

# -F: the base64 payload contains regex metacharacters (+ / =)
if grep -qF "src=\"verify.js\" integrity=\"$SRI\"" "$INDEX_HTML"; then
  UP_TO_DATE=1
else
  UP_TO_DATE=0
fi

if [[ "${1:-}" == "--check" ]]; then
  if (( UP_TO_DATE )); then
    printf 'SRI hash is up to date: %s\n' "$SRI"
    exit 0
  fi
  printf 'SRI hash mismatch — rebuild with: npm run build:verify:sri\n' >&2
  printf '  expected: %s\n' "$SRI" >&2
  printf '  found:    %s\n' \
    "$(grep -oE "$TAG_PATTERN" "$INDEX_HTML" | sed 's/.*integrity="//; s/"$//')" >&2
  exit 1
fi

# Update index.html in-place (macOS and GNU sed compatible)
if sed --version >/dev/null 2>&1; then
  # GNU sed
  sed -i "s|$TAG_PATTERN|src=\"verify.js\" integrity=\"$SRI\"|" "$INDEX_HTML"
else
  # macOS sed
  sed -i '' "s|$TAG_PATTERN|src=\"verify.js\" integrity=\"$SRI\"|" "$INDEX_HTML"
fi

# sed exits 0 when it substitutes nothing, so confirm the write actually landed.
grep -qF "src=\"verify.js\" integrity=\"$SRI\"" "$INDEX_HTML" || {
  printf 'error: SRI substitution did not apply to %s\n' "$INDEX_HTML" >&2
  exit 1
}

printf 'Updated SRI hash: %s\n' "$SRI"
