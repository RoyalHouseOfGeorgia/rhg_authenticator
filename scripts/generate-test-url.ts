/**
 * Generate a test verification URL with a real signed credential.
 *
 * Usage: npx tsx scripts/generate-test-url.ts
 */

import { canonicalize } from '../src/canonical.js';
import { sign, getPublicKey } from '../src/crypto.js';
import { base64urlEncode } from '../src/base64url.js';

// Deterministic test keypair (NOT for production)
const secretKey = new Uint8Array(32);
for (let i = 0; i < 32; i++) secretKey[i] = (42 + i * 7) & 0xff;
const publicKey = getPublicKey(secretKey);

const credential = {
  authority: 'Test Authority',
  date: '2026-03-11',
  detail: 'Test Detail',
  honor: 'Test Honor',
  recipient: 'Jane Doe',
  version: 1,
};

const payloadBytes = canonicalize(credential as Record<string, string | number>);
const signatureBytes = sign(payloadBytes, secretKey);

const p = base64urlEncode(payloadBytes);
const s = base64urlEncode(signatureBytes);

const base = 'http://localhost:8080/verify/';

console.log('=== Test Credential ===');
console.log(`Recipient: ${credential.recipient}`);
console.log(`Honor:     ${credential.honor}`);
console.log(`Detail:    ${credential.detail}`);
console.log(`Date:      ${credential.date}`);
console.log(`Authority: ${credential.authority}`);
console.log();
console.log(`Public key (base64): ${btoa(String.fromCharCode(...publicKey))}`);
console.log();
console.log('=== URLs ===');
console.log();
console.log('Valid credential (should show green "Verified"):');
console.log(`${base}?p=${p}&s=${s}`);
console.log();

// Tampered payload — change recipient
const tampered = canonicalize({
  ...credential,
  recipient: 'Evil Eve',
} as Record<string, string | number>);
const tp = base64urlEncode(tampered);
console.log('Tampered payload (should show red "Not Verified"):');
console.log(`${base}?p=${tp}&s=${s}`);
console.log();

console.log('Missing params (should show amber "Verification Error"):');
console.log(base);
console.log();

console.log('=== Registry Entry ===');
console.log('To make the valid URL work, update keys/registry.json with:');
console.log(JSON.stringify({
  keys: [{
    authority: 'Test Authority',
    from: '2025-01-01',
    to: null,
    algorithm: 'Ed25519',
    public_key: btoa(String.fromCharCode(...publicKey)),
    note: 'Test key for UI preview',
  }],
}, null, 2));
