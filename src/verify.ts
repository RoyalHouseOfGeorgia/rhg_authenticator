/**
 * Credential verification against a key registry.
 *
 * Parses a signed credential payload, iterates all keys in the registry,
 * and verifies the Ed25519 signature. The authority is determined by which
 * registry key successfully verifies the signature. Returns a typed result
 * indicating success (with the matching key) or failure (with a reason).
 */

import { validateCredential, UnsupportedVersionError } from './credential.js';
import {
  isDateInRange,
  decodePublicKey,
} from './registry.js';
import { verify as ed25519Verify } from './crypto.js';

import type { Credential } from './credential.js';
import type { KeyEntry, Registry } from './registry.js';

export type VerificationSuccess = { valid: true; key: KeyEntry; credential: Credential };
export type VerificationFailure = { valid: false; reason: string };
export type VerificationResult = VerificationSuccess | VerificationFailure;

const decoder = new TextDecoder();

/** Maximum allowed payload size in bytes. */
export const MAX_PAYLOAD_BYTES = 2048;

/**
 * Verify a signed credential against a key registry.
 *
 * Parses `payloadBytes` as JSON, validates it as a credential, then iterates
 * all keys in the registry to find one whose Ed25519 signature matches.
 * Verification is performed against the original `payloadBytes`, not a
 * re-canonicalized form. The authority is derived from the matching registry
 * key, not from the credential payload.
 *
 * @param payloadBytes   - UTF-8 encoded JSON credential.
 * @param signatureBytes - 64-byte Ed25519 signature.
 * @param registry       - Key registry to verify against.
 * @returns A result indicating success with the matching key, or failure with a reason.
 */
export function verifyCredential(
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
  registry: Registry,
): VerificationResult {
  // Step 0: Enforce payload size limit.
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    return { valid: false, reason: 'payload exceeds maximum size' };
  }

  // Step 1: Parse payload as JSON.
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(payloadBytes));
  } catch {
    return { valid: false, reason: 'payload is not valid JSON' };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { valid: false, reason: 'payload must be a JSON object' };
  }

  // Step 2: Validate as a credential.
  let credential;
  try {
    credential = validateCredential(parsed);
  } catch (err) {
    if (err instanceof UnsupportedVersionError) {
      return { valid: false, reason: 'credential version not supported' };
    }
    return {
      valid: false,
      reason: 'credential validation failed',
    };
  }

  // Step 3: Validate signature length.
  if (signatureBytes.length !== 64) {
    return { valid: false, reason: 'invalid signature length' };
  }

  // Step 4: Iterate all registry keys — the authority is determined by which key verifies.
  const keys = registry.keys;
  let signatureMatchedButDateInvalid = false;
  let decodeFailures = 0;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    let publicKey: Uint8Array;
    try {
      publicKey = decodePublicKey(key);
    } catch {
      decodeFailures++;
      continue;
    }

    try {
      if (ed25519Verify(signatureBytes, payloadBytes, publicKey)) {
        if (isDateInRange(credential.date, key)) {
          return { valid: true, key, credential };
        }
        signatureMatchedButDateInvalid = true;
      }
    } catch {
      continue;
    }
  }

  if (signatureMatchedButDateInvalid) {
    return {
      valid: false,
      reason: 'signature valid but credential date outside key validity period',
    };
  }
  if (decodeFailures === keys.length) {
    return { valid: false, reason: 'all registry keys failed to decode' };
  }
  return { valid: false, reason: 'no matching key produced a valid signature' };
}
