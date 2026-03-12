/**
 * Key registry schema, validation, lookup, and public key decoding.
 *
 * A registry holds an array of key entries that map authorities to their
 * Ed25519 public keys with validity date ranges.
 */

import { base64Decode } from './base64url.js';

export type KeyEntry = {
  authority: string;
  from: string;
  to: string | null;
  algorithm: 'Ed25519';
  public_key: string;
  note: string;
};

export type Registry = { keys: KeyEntry[] };

const REGISTRY_FIELDS = new Set<string>(['keys']);

const ENTRY_FIELDS = new Set<string>([
  'authority',
  'from',
  'to',
  'algorithm',
  'public_key',
  'note',
]);

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function sanitizeForError(s: string): string {
  return s.replace(/[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
}

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function isValidDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;

  const year = parseInt(value.slice(0, 4), 10);
  const month = parseInt(value.slice(5, 7), 10);
  const day = parseInt(value.slice(8, 10), 10);

  if (year < 1) return false;
  if (month < 1 || month > 12) return false;

  let maxDay = DAYS_IN_MONTH[month - 1];
  if (month === 2 && isLeapYear(year)) maxDay = 29;

  return day >= 1 && day <= maxDay;
}

/** Ed25519 SPKI DER prefix (12 bytes): OID 1.3.101.112 wrapped in SubjectPublicKeyInfo. */
const ED25519_SPKI_PREFIX = new Uint8Array([
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

  return entry as KeyEntry;
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
 * Find all key entries for a given authority.
 *
 * Both the query and each entry's authority are NFC-normalized before
 * comparison.  Comparison is case-sensitive (intentional — authorities are
 * formal names that should match exactly).
 *
 * Results are returned in registry array order.
 */
export function findKeysByAuthority(
  registry: Registry,
  authority: string,
): KeyEntry[] {
  const normalizedQuery = authority.normalize('NFC');
  return registry.keys.filter(
    (entry) => entry.authority.normalize('NFC') === normalizedQuery,
  );
}

/**
 * Check whether a credential date falls within a key's validity range.
 *
 * Uses lexicographic string comparison on ISO 8601 date strings.
 * `from` is inclusive, `to` is inclusive.  `to: null` means no upper bound.
 */
export function isDateInRange(credentialDate: string, key: KeyEntry): boolean {
  if (!DATE_RE.test(credentialDate)) return false;
  if (credentialDate < key.from) return false;
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
