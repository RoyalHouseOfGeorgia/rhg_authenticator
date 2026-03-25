/**
 * Revocation list schema, validation, and hash lookup.
 *
 * A revocation list holds an array of entries mapping SHA-256 payload
 * hashes to revocation dates, enabling O(1) lookup of revoked credentials.
 */

import { sanitizeForError } from './credential.js';
import { isValidDate } from './validation.js';

export type RevocationEntry = {
  hash: string;       // lowercase hex SHA-256
  revoked_on: string; // YYYY-MM-DD
};

export type RevocationList = {
  revocations: RevocationEntry[];
};

export const MAX_REVOCATION_ENTRIES = 10000;

const HEX_64_RE = /^[0-9a-f]{64}$/;

const ROOT_FIELDS = new Set<string>(['revocations']);
const ENTRY_FIELDS = new Set<string>(['hash', 'revoked_on']);

function validateEntry(entry: unknown, index: number): RevocationEntry {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error(`revocations[${index}] must be a plain object`);
  }

  const record = entry as Record<string, unknown>;

  // Reject extra fields.
  for (const key of Object.keys(record)) {
    if (!ENTRY_FIELDS.has(key)) {
      throw new Error(`revocations[${index}]: unexpected field: ${key}`);
    }
  }

  // hash: required, 64-char lowercase hex (accept uppercase, normalize).
  if (!('hash' in record)) {
    throw new Error(`revocations[${index}]: missing required field: hash`);
  }
  if (typeof record.hash !== 'string') {
    throw new Error(`revocations[${index}]: hash must be a string`);
  }
  const normalizedHash = record.hash.toLowerCase();
  if (!HEX_64_RE.test(normalizedHash)) {
    throw new Error(
      `revocations[${index}]: hash must be a 64-character hex string: ${sanitizeForError(record.hash)}`,
    );
  }

  // revoked_on: required, valid YYYY-MM-DD.
  if (!('revoked_on' in record)) {
    throw new Error(`revocations[${index}]: missing required field: revoked_on`);
  }
  if (typeof record.revoked_on !== 'string') {
    throw new Error(`revocations[${index}]: revoked_on must be a string`);
  }
  if (!isValidDate(record.revoked_on)) {
    throw new Error(
      `revocations[${index}]: invalid date for revoked_on: ${sanitizeForError(record.revoked_on)}`,
    );
  }

  return { hash: normalizedHash, revoked_on: record.revoked_on };
}

/** Validate an unknown value as a RevocationList, throwing on any violation. */
export function validateRevocationList(data: unknown): RevocationList {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('revocation list must be a plain object');
  }

  const record = data as Record<string, unknown>;

  if (!('revocations' in record)) {
    throw new Error('missing required field: revocations');
  }
  if (!Array.isArray(record.revocations)) {
    throw new Error('revocations must be an array');
  }
  if (record.revocations.length > MAX_REVOCATION_ENTRIES) {
    throw new Error(
      `revocation list exceeds maximum entry count (${MAX_REVOCATION_ENTRIES})`,
    );
  }

  // Reject extra top-level fields.
  for (const key of Object.keys(record)) {
    if (!ROOT_FIELDS.has(key)) {
      throw new Error(`unexpected field: ${key}`);
    }
  }

  const seen = new Set<string>();
  const entries: RevocationEntry[] = [];
  for (let i = 0; i < record.revocations.length; i++) {
    const entry = validateEntry(record.revocations[i], i);
    if (!seen.has(entry.hash)) {
      seen.add(entry.hash);
      entries.push(entry);
    }
  }

  return { revocations: entries };
}

/** Build an O(1) lookup set of lowercase hex hashes from a validated revocation list. */
export function buildRevocationSet(list: RevocationList): Set<string> {
  return new Set(list.revocations.map((e) => e.hash));
}

/** Check whether a payload hash appears in the revocation set (case-insensitive). */
export function isRevoked(
  payloadHash: string,
  revocationSet: Set<string>,
): boolean {
  return revocationSet.has(payloadHash.toLowerCase());
}
