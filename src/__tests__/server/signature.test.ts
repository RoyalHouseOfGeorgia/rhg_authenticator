import { describe, expect, it } from 'vitest';
import { validateSignatureLength } from '../../server/signature.js';

describe('validateSignatureLength', () => {
  it('returns the same bytes for a 64-byte input', () => {
    const sig = new Uint8Array(64);
    sig[0] = 0xab;
    sig[63] = 0xcd;
    const result = validateSignatureLength(sig);
    expect(result).toEqual(sig);
  });

  it('returns the same reference for a 64-byte input', () => {
    const sig = new Uint8Array(64);
    const result = validateSignatureLength(sig);
    expect(result).toBe(sig);
  });

  it('throws for 63 bytes with byte count in message', () => {
    expect(() => validateSignatureLength(new Uint8Array(63))).toThrow(
      'Expected 64-byte Ed25519 signature, got 63 bytes',
    );
  });

  it('throws for 65 bytes with byte count in message', () => {
    expect(() => validateSignatureLength(new Uint8Array(65))).toThrow(
      'Expected 64-byte Ed25519 signature, got 65 bytes',
    );
  });

  it('throws for 0 bytes', () => {
    expect(() => validateSignatureLength(new Uint8Array(0))).toThrow(
      'Expected 64-byte Ed25519 signature, got 0 bytes',
    );
  });

  it('throws for 128 bytes', () => {
    expect(() => validateSignatureLength(new Uint8Array(128))).toThrow(
      'Expected 64-byte Ed25519 signature, got 128 bytes',
    );
  });
});
