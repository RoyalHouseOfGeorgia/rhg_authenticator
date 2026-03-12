/**
 * Credential verification against a key registry.
 *
 * Parses a signed credential payload, looks up the authority's keys in the
 * registry, and verifies the Ed25519 signature. Returns a typed result
 * indicating success (with the matching key) or failure (with a reason).
 */

import { validateCredential, UnsupportedVersionError } from './credential.js';
import {
  findKeysByAuthority,
  isDateInRange,
  decodePublicKey,
} from './registry.js';
import { verify as ed25519Verify } from './crypto.js';

import type { KeyEntry, Registry } from './registry.js';

export type VerificationSuccess = { valid: true; key: KeyEntry };
export type VerificationFailure = { valid: false; reason: string };
export type VerificationResult = VerificationSuccess | VerificationFailure;

const decoder = new TextDecoder();

/** Maximum allowed payload size in bytes. */
export const MAX_PAYLOAD_BYTES = 2048;

/**
 * Verify a signed credential against a key registry.
 *
 * Parses `payloadBytes` as JSON, validates it as a credential, looks up keys
 * for the credential's authority, and checks the Ed25519 signature. Verification
 * is performed against the original `payloadBytes`, not a re-canonicalized form.
 *
 * @param payloadBytes   - UTF-8 encoded JSON credential.
 * @param signatureBytes - 64-byte Ed25519 signature.
 * @param registry       - Key registry to look up authority keys.
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

  // Step 3: Look up authority keys.
  const keys = findKeysByAuthority(registry, credential.authority);
  if (keys.length === 0) {
    return { valid: false, reason: 'authority not found in registry' };
  }

  // Step 4: First pass — date-eligible keys.
  const triedKeys = new Set<KeyEntry>();
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (!isDateInRange(credential.date, key)) continue;
    triedKeys.add(key);

    let publicKey: Uint8Array;
    try {
      publicKey = decodePublicKey(key);
    } catch {
      if (typeof console !== 'undefined')
        console.warn('Skipping malformed registry key at index', i);
      continue;
    }

    try {
      if (ed25519Verify(signatureBytes, payloadBytes, publicKey)) {
        return { valid: true, key };
      }
    } catch {
      continue;
    }
  }

  // Step 5: Second pass — remaining keys (for diagnostics).
  let dateMismatch = false;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (triedKeys.has(key)) continue;

    let publicKey: Uint8Array;
    try {
      publicKey = decodePublicKey(key);
    } catch {
      if (typeof console !== 'undefined')
        console.warn('Skipping malformed registry key at index', i);
      continue;
    }

    try {
      if (ed25519Verify(signatureBytes, payloadBytes, publicKey)) {
        dateMismatch = true;
      }
    } catch {
      continue;
    }
  }

  // Step 6: Date mismatch diagnostic.
  if (dateMismatch) {
    return {
      valid: false,
      reason: 'signature valid but credential date outside key validity period',
    };
  }

  // Step 7: No match.
  return { valid: false, reason: 'no matching key produced a valid signature' };
}
