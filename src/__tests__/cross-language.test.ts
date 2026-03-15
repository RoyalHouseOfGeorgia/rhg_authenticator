import { describe, it, expect } from 'vitest';
import { canonicalize } from '../canonical.js';
import { verify } from '../crypto.js';
import { base64urlDecode } from '../base64url.js';
import vectors from './fixtures/vectors.json';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

describe('cross-language test vectors', () => {
  it('has at least 3 test vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const vector of vectors) {
    describe(`vector: ${vector.name}`, () => {
      it('canonicalizes to the expected hex', () => {
        const canonical = canonicalize(
          vector.credential as Record<string, string | number>,
        );
        expect(toHex(canonical)).toBe(vector.canonical_hex);
      });

      it('verifies the signature', () => {
        const payload = base64urlDecode(vector.payload_b64url);
        const signature = base64urlDecode(vector.signature_b64url);
        const publicKey = hexToBytes(vector.public_key_hex);
        const isValid = verify(signature, payload, publicKey);
        expect(isValid).toBe(true);
      });
    });
  }
});
