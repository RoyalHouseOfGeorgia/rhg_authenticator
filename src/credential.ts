/**
 * Credential schema definition and validation for v1 credentials.
 *
 * Validates structure, types, whitespace, extra keys, and date correctness
 * without relying on the Date constructor (which silently rolls invalid dates).
 */

import { isValidDate } from './validation.js';

export type CredentialV1 = {
  authority: string;
  date: string;
  detail: string;
  honor: string;
  recipient: string;
  version: 1;
};

export type Credential = CredentialV1;

/** Strips C0/C1 control characters and bidi overrides. Does not handle zero-width joiners or length limits — callers are responsible for truncation. */
export function sanitizeForError(s: string): string {
  return s.replace(/[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
}

export class UnsupportedVersionError extends Error {
  constructor(version: unknown) {
    const safeVersion = typeof version === 'number' ? String(version) : sanitizeForError(String(version));
    super(`Unsupported credential version: ${safeVersion}`);
    this.name = 'UnsupportedVersionError';
  }
}

const STRING_FIELDS = ['authority', 'date', 'detail', 'honor', 'recipient'] as const;
const ALL_FIELDS = new Set<string>([...STRING_FIELDS, 'version']);

/** Validate an unknown value as a v1 Credential, throwing on any violation. */
export function validateCredential(obj: unknown): Credential {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('credential must be a plain object');
  }

  const record = obj as Record<string, unknown>;

  // Version check first.
  if (!('version' in record)) {
    throw new Error('missing required field: version');
  }
  if (typeof record.version !== 'number') {
    throw new Error('version must be a number');
  }
  if (record.version !== 1) {
    throw new UnsupportedVersionError(record.version);
  }

  // Required string fields.
  for (const field of STRING_FIELDS) {
    if (!(field in record)) {
      throw new Error(`missing required field: ${field}`);
    }
    const value = record[field];
    if (typeof value !== 'string') {
      throw new Error(`${field} must be a string`);
    }
    if (value !== value.trim()) {
      throw new Error(`${field} must not have leading or trailing whitespace`);
    }
    if (value.length === 0) {
      throw new Error(`${field} must not be empty`);
    }
  }

  // Reject extra keys.
  for (const key of Object.keys(record)) {
    if (!ALL_FIELDS.has(key)) {
      throw new Error(`unexpected field: ${key}`);
    }
  }

  // Date validation.
  if (!isValidDate(record.date as string)) {
    throw new Error(`invalid date: ${sanitizeForError(record.date as string)}`);
  }

  return obj as Credential;
}
