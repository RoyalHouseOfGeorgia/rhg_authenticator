/**
 * Credential schema definition and validation for v1 credentials.
 *
 * Validates structure, types, whitespace, extra keys, and date correctness
 * without relying on the Date constructor (which silently rolls invalid dates).
 */

export type CredentialV1 = {
  authority: string;
  date: string;
  detail: string;
  honor: string;
  recipient: string;
  version: 1;
};

export type Credential = CredentialV1;

function sanitizeForError(s: string): string {
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

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

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
