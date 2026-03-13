/**
 * Validate that a signature is exactly 64 bytes (raw Ed25519 R||S).
 * Ed25519 signatures are never DER-wrapped (unlike ECDSA).
 * Throws with descriptive error if length is wrong.
 */
export function validateSignatureLength(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new Error(
      `Expected 64-byte Ed25519 signature, got ${raw.length} bytes`,
    );
  }
  return raw;
}
