#!/usr/bin/env bash
set -euo pipefail
umask 077

# Generate the self-signed macOS release code-signing certificate.
# Usage: ./scripts/gen-macos-cert.sh <openssl-binary> <outdir>
#
# <openssl-binary> must be OpenSSL 3 (macOS /usr/bin/openssl is LibreSSL; use
# Homebrew's openssl@3). Writes to <outdir>:
#   cert.p12        PKCS#12 (key + cert), legacy PBE so macOS `security import` accepts it
#   cert.p12.b64    cert.p12 as one base64 line  -> MACOS_SIGNING_P12
#   password.txt    random p12 password          -> MACOS_SIGNING_P12_PASSWORD
#   requirement.txt code-signing requirement     -> go/update/requirement.go PinnedRequirement
#   cert.pem        the public certificate
# The unencrypted private key is deleted once the p12 is built. All logging goes
# to stderr; stdout stays empty. Shared by the one-time setup and the CI dry-run
# job, so this is the single source of the certificate recipe.

if [[ $# -ne 2 || -z "$1" || -z "$2" ]]; then
  printf 'usage: %s <openssl-binary> <outdir>\n' "$0" >&2
  exit 2
fi
OPENSSL="$1"
OUTDIR="$2"

log() { printf '%s\n' "$*" >&2; }

for f in cert.p12 cert.p12.b64 password.txt requirement.txt cert.pem key.pem; do
  if [[ -e "$OUTDIR/$f" ]]; then
    log "error: $OUTDIR/$f already exists; refusing to overwrite"
    exit 1
  fi
done

command -v "$OPENSSL" >/dev/null || { log "error: $OPENSSL not found"; exit 1; }
OPENSSL_VERSION=$("$OPENSSL" version)
log "Using: $OPENSSL_VERSION"
# LibreSSL (macOS /usr/bin/openssl) builds a p12 that macOS `security import`
# rejects, and that would only surface when sign-macos fails on a release tag.
[[ "$OPENSSL_VERSION" == "OpenSSL 3."* ]] || { log "error: need OpenSSL 3, got: $OPENSSL_VERSION"; exit 1; }

CERT_DAYS=7305 # 20 years including leap days; replacing the cert forces a manual reinstall
mkdir -p "$OUTDIR"
cd "$OUTDIR"
# Never leave the unencrypted private key behind; on failure also remove the
# partial outputs (incl. password.txt) so a rerun into the same dir works.
cleanup() {
  local rc=$?
  rm -f key.pem
  if [[ $rc -ne 0 ]]; then rm -f cert.p12 cert.p12.b64 password.txt requirement.txt cert.pem; fi
}
trap cleanup EXIT

# The password exists first so the private key is never written unencrypted
# (rm does not erase SSD blocks or backups). RSA-3072: the key is pinned for 20
# years and changing it forces every user to reinstall by hand.
"$OPENSSL" rand -base64 32 | tr -d '\n' > password.txt
"$OPENSSL" req -x509 -newkey rsa:3072 -passout file:password.txt -days "$CERT_DAYS" \
  -keyout key.pem -out cert.pem \
  -subj "/CN=RHG Authenticator Release" \
  -addext "basicConstraints=critical,CA:false" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=critical,codeSigning" >&2
# Same password in and out via env: given one file for both -passin and
# -passout, openssl reads line 1 as input and line 2 as output.
RHG_P12_PW=$(cat password.txt) "$OPENSSL" pkcs12 -export -inkey key.pem -passin env:RHG_P12_PW \
  -in cert.pem -name "RHG Authenticator Release" \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -passout env:RHG_P12_PW -out cert.p12 >&2
rm -f key.pem
"$OPENSSL" base64 -A -in cert.p12 > cert.p12.b64

H=$("$OPENSSL" x509 -in cert.pem -noout -fingerprint -sha1 | cut -d= -f2 | tr -d : | tr '[:upper:]' '[:lower:]')
if [[ ! "$H" =~ ^[0-9a-f]{40}$ ]]; then
  log "error: unexpected SHA-1 fingerprint '$H'"
  exit 1
fi
printf 'identifier "ge.royalhouseofgeorgia.rhg-authenticator" and certificate leaf = H"%s"\n' "$H" > requirement.txt

# Sanity: the p12 opens with the generated password.
"$OPENSSL" pkcs12 -in cert.p12 -passin file:password.txt -noout >&2

log "Wrote cert.p12, cert.p12.b64, password.txt, requirement.txt, cert.pem to $OUTDIR"
log "Requirement: $(cat requirement.txt)"
