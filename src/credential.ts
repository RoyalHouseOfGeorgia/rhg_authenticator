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

/** Pattern matching C0/C1 control characters and bidi overrides. Exported as a string constant (not a RegExp with `g`) to avoid `lastIndex` statefulness. */
export const CONTROL_CHAR_PATTERN = '[\\x00-\\x1f\\x7f-\\x9f\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]';

/** Cached test-only regex (no `g` flag, safe to reuse — no `lastIndex` state). */
const CONTROL_CHAR_RE = new RegExp(CONTROL_CHAR_PATTERN);

/**
 * Strips C0/C1 control characters and bidi overrides. Does not handle
 * zero-width joiners or length limits — callers are responsible for truncation.
 *
 * Note: creates a new RegExp per call because the `g` flag carries `lastIndex`
 * state that would make a shared instance unsafe across calls.
 */
export function sanitizeForError(s: string): string {
  return s.replace(new RegExp(CONTROL_CHAR_PATTERN, 'g'), '');
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

const FIELD_MAX_LENGTHS = {
  authority: 200,
  recipient: 500,
  honor: 200,
  detail: 2000,
  date: 10,
} as const satisfies Record<(typeof STRING_FIELDS)[number], number>;

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
    if (CONTROL_CHAR_RE.test(value)) {
      throw new Error(`${field} contains invalid control characters`);
    }
    const codePointLength = [...value].length;
    if (codePointLength === 0) {
      throw new Error(`${field} must not be empty`);
    }
    if (codePointLength > FIELD_MAX_LENGTHS[field]) {
      throw new Error(`${field} exceeds maximum length of ${FIELD_MAX_LENGTHS[field]}`);
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
