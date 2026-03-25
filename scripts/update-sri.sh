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

if [[ "${1:-}" == "--check" ]]; then
  if grep -q "$SRI" "$INDEX_HTML"; then
    printf 'SRI hash is up to date: %s\n' "$SRI"
    exit 0
  else
    printf 'SRI hash mismatch — rebuild with: npm run build:verify:sri\n' >&2
    exit 1
  fi
fi

# Update index.html in-place (macOS and GNU sed compatible)
if sed --version >/dev/null 2>&1; then
  # GNU sed
  sed -i "s|integrity=\"sha384-[A-Za-z0-9+/=]*\"|integrity=\"$SRI\"|" "$INDEX_HTML"
else
  # macOS sed
  sed -i '' "s|integrity=\"sha384-[A-Za-z0-9+/=]*\"|integrity=\"$SRI\"|" "$INDEX_HTML"
fi

printf 'Updated SRI hash: %s\n' "$SRI"
