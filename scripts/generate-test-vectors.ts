/**
 * Generate cross-language test vectors for Go signing tests.
 *
 * Usage: npx tsx scripts/generate-test-vectors.ts > go/testdata/vectors.json
 */

import { canonicalize } from '../src/canonical.js';
import { base64urlEncode } from '../src/base64url.js';
import { sign, getPublicKey } from '../src/crypto.js';

const VERIFY_BASE_URL = 'https://verify.royalhouseofgeorgia.ge/';

// Deterministic test key: first byte 0x01, rest zeros.
const secretKey = new Uint8Array(32);
secretKey[0] = 0x01;

const publicKey = getPublicKey(secretKey);

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

type Credential = {
  version: number;
  authority: string;
  recipient: string;
  honor: string;
  detail: string;
  date: string;
};

function generateVector(name: string, credential: Credential) {
  const canonical = canonicalize(credential as unknown as Record<string, string | number>);
  const payloadB64 = base64urlEncode(canonical);
  const signature = sign(canonical, secretKey);
  const signatureB64 = base64urlEncode(signature);
  const url = `${VERIFY_BASE_URL}?p=${payloadB64}&s=${signatureB64}`;

  return {
    name,
    credential,
    canonical_hex: toHex(canonical),
    payload_b64url: payloadB64,
    signature_b64url: signatureB64,
    url,
    public_key_hex: toHex(publicKey),
  };
}

const vectors = [
  generateVector('ascii_only', {
    version: 1,
    authority: 'Test Authority',
    recipient: 'John Doe',
    honor: 'Test Honor',
    detail: 'For service',
    date: '2026-03-13',
  }),
  generateVector('georgian_text', {
    version: 1,
    authority: 'Test Authority',
    recipient: '\u10E5\u10D0\u10E0\u10D7\u10D5\u10D4\u10DA\u10D8',
    honor: 'Test Honor',
    detail: '\u10E1\u10D0\u10E5\u10D0\u10E0\u10D7\u10D5\u10D4\u10DA\u10DD\u10E1 \u10E1\u10D0\u10DB\u10D4\u10E4\u10DD',
    date: '2026-03-13',
  }),
  generateVector('nfc_edge_case', {
    version: 1,
    authority: 'Test Authority',
    recipient: 'Caf\u0065\u0301',  // NFD é
    honor: 'Test Honor',
    detail: 're\u0301sume\u0301',  // NFD résumé
    date: '2026-03-13',
  }),
];

console.log(JSON.stringify(vectors, null, 2));
