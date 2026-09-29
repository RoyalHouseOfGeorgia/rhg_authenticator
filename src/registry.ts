/**
 * Key registry schema, validation, lookup, and public key decoding.
 *
 * A registry holds an array of key entries that map authorities to their
 * Ed25519 public keys. A key's `to` date bounds which credential dates it
 * verifies (`from` is informational). An optional `allowed_honors` list
 * restricts a key to specific honors; when absent the key is unrestricted.
 */

import { base64Decode } from './base64url.js';
import { CONTROL_CHAR_RE, sanitizeForError } from './credential.js';
import { DATE_RE, isValidDate } from './validation.js';

export type KeyEntry = {
  authority: string;
  from: string;
  to: string | null;
  algorithm: 'Ed25519';
  public_key: string;
  note: string;
  allowed_honors?: string[];
};

export type Registry = { keys: KeyEntry[] };

const REGISTRY_FIELDS = new Set<string>(['keys']);

export const MAX_REGISTRY_KEYS = 1000;

const ENTRY_FIELDS = new Set<string>([
  'authority',
  'from',
  'to',
  'algorithm',
  'public_key',
  'note',
  'allowed_honors',
]);

/** Ed25519 SPKI DER prefix (12 bytes): OID 1.3.101.112 wrapped in SubjectPublicKeyInfo. */
export const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function validateEntry(entry: unknown, index: number): KeyEntry {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error(`keys[${index}] must be a plain object`);
  }

  const record = entry as Record<string, unknown>;

  // Reject extra fields.
  for (const key of Object.keys(record)) {
    if (!ENTRY_FIELDS.has(key)) {
      throw new Error(`keys[${index}]: unexpected field: ${key}`);
    }
  }

  // authority: non-empty string.
  if (!('authority' in record)) {
    throw new Error(`keys[${index}]: missing required field: authority`);
  }
  if (typeof record.authority !== 'string') {
    throw new Error(`keys[${index}]: authority must be a string`);
  }
  if (record.authority.length === 0) {
    throw new Error(`keys[${index}]: authority must not be empty`);
  }
  if (CONTROL_CHAR_RE.test(record.authority)) {
    throw new Error(`keys[${index}]: authority contains invalid control characters`);
  }
  // NFC-normalize authority so lookups can use plain comparison.
  const normalizedAuthority = record.authority.normalize('NFC');

  // from: valid date string.
  if (!('from' in record)) {
    throw new Error(`keys[${index}]: missing required field: from`);
  }
  if (typeof record.from !== 'string') {
    throw new Error(`keys[${index}]: from must be a string`);
  }
  if (!isValidDate(record.from)) {
    throw new Error(`keys[${index}]: invalid date for from: ${sanitizeForError(record.from as string)}`);
  }

  // to: valid date string or null.
  if (!('to' in record)) {
    throw new Error(`keys[${index}]: missing required field: to`);
  }
  if (record.to !== null) {
    if (typeof record.to !== 'string') {
      throw new Error(`keys[${index}]: to must be a string or null`);
    }
    if (!isValidDate(record.to)) {
      throw new Error(`keys[${index}]: invalid date for to: ${sanitizeForError(record.to as string)}`);
    }
  }

  if (typeof record.to === 'string' && record.to < record.from) {
    throw new Error(`keys[${index}]: invalid date range: from (${sanitizeForError(record.from as string)}) is after to (${sanitizeForError(record.to as string)})`);
  }

  // algorithm: exactly 'Ed25519'.
  if (!('algorithm' in record)) {
    throw new Error(`keys[${index}]: missing required field: algorithm`);
  }
  if (record.algorithm !== 'Ed25519') {
    throw new Error(`keys[${index}]: algorithm must be 'Ed25519'`);
  }

  // public_key: non-empty string.
  if (!('public_key' in record)) {
    throw new Error(`keys[${index}]: missing required field: public_key`);
  }
  if (typeof record.public_key !== 'string') {
    throw new Error(`keys[${index}]: public_key must be a string`);
  }
  if (record.public_key.length === 0) {
    throw new Error(`keys[${index}]: public_key must not be empty`);
  }

  // note: string (can be empty).
  if (!('note' in record)) {
    throw new Error(`keys[${index}]: missing required field: note`);
  }
  if (typeof record.note !== 'string') {
    throw new Error(`keys[${index}]: note must be a string`);
  }
  if (CONTROL_CHAR_RE.test(record.note)) {
    throw new Error(`keys[${index}]: note contains invalid control characters`);
  }

  // allowed_honors: optional non-empty array of non-empty, trimmed strings.
  // `in` (not `!== undefined`) so an explicit null is rejected, not treated as absent.
  let allowedHonors: string[] | undefined;
  if ('allowed_honors' in record) {
    if (!Array.isArray(record.allowed_honors) || record.allowed_honors.length === 0) {
      throw new Error(`keys[${index}]: allowed_honors must be a non-empty array`);
    }
    allowedHonors = record.allowed_honors.map((honor: unknown, j: number) => {
      if (typeof honor !== 'string' || honor.length === 0) {
        throw new Error(`keys[${index}]: allowed_honors[${j}] must be a non-empty string`);
      }
      if (CONTROL_CHAR_RE.test(honor)) {
        throw new Error(`keys[${index}]: allowed_honors[${j}] contains invalid control characters`);
      }
      if (honor !== honor.trim()) {
        throw new Error(`keys[${index}]: allowed_honors[${j}] must not have leading or trailing whitespace`);
      }
      return honor;
    });
  }

  const validated: KeyEntry = {
    authority: normalizedAuthority,
    from: record.from as string,
    to: record.to as string | null,
    algorithm: record.algorithm as 'Ed25519',
    public_key: record.public_key as string,
    note: record.note as string,
  };
  if (allowedHonors !== undefined) {
    validated.allowed_honors = allowedHonors;
  }
  return validated;
}

/** Validate an unknown value as a Registry, throwing on any violation. */
export function validateRegistry(obj: unknown): Registry {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('registry must be a plain object');
  }

  const record = obj as Record<string, unknown>;

  if (!('keys' in record)) {
    throw new Error('missing required field: keys');
  }
  if (!Array.isArray(record.keys)) {
    throw new Error('keys must be an array');
  }
  if (record.keys.length === 0) {
    throw new Error('keys array must not be empty');
  }
  if (record.keys.length > MAX_REGISTRY_KEYS) {
    throw new Error(`registry exceeds maximum key count (${MAX_REGISTRY_KEYS})`);
  }

  // Reject extra top-level fields.
  // Note: Object.keys does NOT enumerate __proto__ after JSON.parse, so this
  // check cannot catch __proto__ at the registry level. Not a real attack vector
  // since the value is inaccessible via Object.keys iteration.
  for (const key of Object.keys(record)) {
    if (!REGISTRY_FIELDS.has(key)) {
      throw new Error(`unexpected field: ${key}`);
    }
  }

  const entries: KeyEntry[] = [];
  for (let i = 0; i < record.keys.length; i++) {
    entries.push(validateEntry(record.keys[i], i));
  }

  return { keys: entries };
}

/**
 * Check whether a credential date is within a key's validity.
 *
 * Only `to` limits validity (inclusive; `null` means no upper bound). `from`
 * is informational and does not restrict, so backdated credentials verify.
 * Uses lexicographic string comparison on ISO 8601 date strings.
 */
export function isDateInRange(credentialDate: string, key: KeyEntry): boolean {
  if (!DATE_RE.test(credentialDate)) return false;
  if (key.to !== null && credentialDate > key.to) return false;
  return true;
}

/**
 * Decode a key entry's `public_key` field to raw 32-byte Ed25519 key material.
 *
 * Accepts either:
 * - 44-byte DER/SPKI encoding (strips the 12-byte prefix)
 * - 32-byte raw key (used as-is)
 *
 * Throws with a clear message for any other length.
 */
export function decodePublicKey(entry: KeyEntry): Uint8Array {
  const bytes = base64Decode(entry.public_key);

  if (bytes.length === 44) {
    // Verify SPKI prefix.
    for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
      if (bytes[i] !== ED25519_SPKI_PREFIX[i]) {
        throw new Error(
          `decodePublicKey: 44-byte key does not have expected Ed25519 SPKI prefix`,
        );
      }
    }
    return bytes.slice(ED25519_SPKI_PREFIX.length);
  }

  if (bytes.length === 32) {
    return bytes;
  }

  throw new Error(
    `decodePublicKey: unexpected key length ${bytes.length} bytes (expected 32 or 44)`,
  );
}
