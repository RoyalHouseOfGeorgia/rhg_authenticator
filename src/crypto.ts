/**
 * Ed25519 signing, verification, and key derivation.
 *
 * Thin wrappers around `@noble/curves/ed25519`. Caller should understand
 * they are working with Ed25519 keys and signatures.
 */

import { ed25519 } from "@noble/curves/ed25519";

/**
 * Sign a message with an Ed25519 secret key.
 *
 * @param message  - Arbitrary-length message bytes.
 * @param secretKey - 32-byte Ed25519 private key.
 * @returns 64-byte Ed25519 signature.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (!(message instanceof Uint8Array)) {
    throw new TypeError("message must be a Uint8Array");
  }
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) {
    throw new TypeError(
      `secretKey must be exactly 32 bytes, got ${secretKey instanceof Uint8Array ? secretKey.length : typeof secretKey}`,
    );
  }
  return ed25519.sign(message, secretKey);
}

/**
 * Verify an Ed25519 signature against a message and public key.
 *
 * Uses strict RFC 8032 verification (zip215: false).
 *
 * @param signature - 64-byte Ed25519 signature.
 * @param message   - The original message bytes.
 * @param publicKey - 32-byte Ed25519 public key.
 * @returns `true` if valid, `false` otherwise.
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new TypeError(
      `signature must be exactly 64 bytes, got ${signature instanceof Uint8Array ? signature.length : typeof signature}`,
    );
  }
  if (!(message instanceof Uint8Array)) {
    throw new TypeError("message must be a Uint8Array");
  }
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new TypeError(
      `publicKey must be exactly 32 bytes, got ${publicKey instanceof Uint8Array ? publicKey.length : typeof publicKey}`,
    );
  }
  return ed25519.verify(signature, message, publicKey, { zip215: false });
}

/**
 * Derive the Ed25519 public key from a 32-byte secret key.
 *
 * @param secretKey - 32-byte Ed25519 private key.
 * @returns 32-byte Ed25519 public key.
 */
export function getPublicKey(secretKey: Uint8Array): Uint8Array {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) {
    throw new TypeError(
      `secretKey must be exactly 32 bytes, got ${secretKey instanceof Uint8Array ? secretKey.length : typeof secretKey}`,
    );
  }
  return ed25519.getPublicKey(secretKey);
}
