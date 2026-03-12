import { describe, expect, it } from 'vitest';
import {
  validateCredential,
  UnsupportedVersionError,
} from '../credential.js';
import type { Credential } from '../credential.js';

const validCredential = {
  authority: 'Test Authority',
  date: '2026-03-11',
  detail: 'Test Detail',
  honor: 'Test Honor',
  recipient: 'Jane Doe',
  version: 1,
};

describe('validateCredential', () => {
  it('accepts a valid v1 credential and returns it typed', () => {
    const result: Credential = validateCredential({ ...validCredential });
    expect(result).toEqual(validCredential);
    expect(result.version).toBe(1);
  });

  describe('rejects non-object inputs', () => {
    it('throws on null', () => {
      expect(() => validateCredential(null)).toThrow(
        'credential must be a plain object',
      );
    });

    it('throws on an array', () => {
      expect(() => validateCredential([1, 2, 3])).toThrow(
        'credential must be a plain object',
      );
    });

    it('throws on a number', () => {
      expect(() => validateCredential(42)).toThrow(
        'credential must be a plain object',
      );
    });

    it('throws on a string', () => {
      expect(() => validateCredential('hello')).toThrow(
        'credential must be a plain object',
      );
    });

    it('throws on undefined', () => {
      expect(() => validateCredential(undefined)).toThrow(
        'credential must be a plain object',
      );
    });
  });

  describe('missing required fields', () => {
    it('throws when version is missing', () => {
      const { version: _, ...rest } = validCredential;
      expect(() => validateCredential(rest)).toThrow(
        'missing required field: version',
      );
    });

    it('throws when authority is missing', () => {
      const { authority: _, ...rest } = validCredential;
      expect(() => validateCredential(rest)).toThrow(
        'missing required field: authority',
      );
    });

    it('throws when date is missing', () => {
      const { date: _, ...rest } = validCredential;
      expect(() => validateCredential(rest)).toThrow(
        'missing required field: date',
      );
    });

    it('throws when honor is missing', () => {
      const { honor: _, ...rest } = validCredential;
      expect(() => validateCredential(rest)).toThrow(
        'missing required field: honor',
      );
    });

    it('throws when recipient is missing', () => {
      const { recipient: _, ...rest } = validCredential;
      expect(() => validateCredential(rest)).toThrow(
        'missing required field: recipient',
      );
    });
  });

  describe('version validation', () => {
    it('throws UnsupportedVersionError for version 2', () => {
      const cred = { ...validCredential, version: 2 };
      expect(() => validateCredential(cred)).toThrow(UnsupportedVersionError);
      expect(() => validateCredential(cred)).toThrow(
        'Unsupported credential version: 2',
      );
    });

    it('throws UnsupportedVersionError for version 0', () => {
      expect(() =>
        validateCredential({ ...validCredential, version: 0 }),
      ).toThrow(UnsupportedVersionError);
    });

    it('throws when version is a string instead of a number', () => {
      const cred = { ...validCredential, version: '1' };
      expect(() => validateCredential(cred)).toThrow('version must be a number');
    });

    it('throws when version is null', () => {
      const cred = { ...validCredential, version: null };
      expect(() => validateCredential(cred)).toThrow('version must be a number');
    });
  });

  describe('UnsupportedVersionError sanitization', () => {
    it('strips control characters from string version', () => {
      const err = new UnsupportedVersionError('\x1b[31mevil\x1b[0m');
      expect(err.message).toBe('Unsupported credential version: [31mevil[0m');
      expect(err.message).not.toMatch(/\x1b/);
    });

    it('passes through HTML tags (sanitizeForError only strips control/bidi chars)', () => {
      const err = new UnsupportedVersionError('<script>alert(1)</script>');
      expect(err.message).toBe('Unsupported credential version: <script>alert(1)</script>');
    });

    it('preserves numeric version 0 in message', () => {
      const err = new UnsupportedVersionError(0);
      expect(err.message).toBe('Unsupported credential version: 0');
    });

    it('preserves numeric version -1 in message', () => {
      const err = new UnsupportedVersionError(-1);
      expect(err.message).toBe('Unsupported credential version: -1');
    });

    it('preserves NaN in message', () => {
      const err = new UnsupportedVersionError(NaN);
      expect(err.message).toBe('Unsupported credential version: NaN');
    });

    it('has name set to UnsupportedVersionError', () => {
      const err = new UnsupportedVersionError(99);
      expect(err.name).toBe('UnsupportedVersionError');
    });
  });

  describe('date validation', () => {
    it('rejects month 13', () => {
      const cred = { ...validCredential, date: '2026-13-01' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-13-01');
    });

    it('rejects February 30', () => {
      const cred = { ...validCredential, date: '2026-02-30' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-02-30');
    });

    it('rejects wrong format (natural language)', () => {
      const cred = { ...validCredential, date: 'March 11, 2026' };
      expect(() => validateCredential(cred)).toThrow(
        'invalid date: March 11, 2026',
      );
    });

    it('rejects month 0', () => {
      const cred = { ...validCredential, date: '2026-00-15' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-00-15');
    });

    it('rejects day 0', () => {
      const cred = { ...validCredential, date: '2026-01-00' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-01-00');
    });

    it('rejects day 32 in January', () => {
      const cred = { ...validCredential, date: '2026-01-32' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-01-32');
    });

    it('rejects April 31', () => {
      const cred = { ...validCredential, date: '2026-04-31' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-04-31');
    });

    it('sanitizes control characters in date error messages', () => {
      const cred = { ...validCredential, date: '2026-99-99\nINFO: fake' };
      expect(() => validateCredential(cred)).toThrow(/invalid date/);
      try {
        validateCredential(cred);
      } catch (e) {
        expect((e as Error).message).not.toMatch(/\n/);
      }
    });

    it('sanitizes bidi override characters in date error messages', () => {
      const cred = { ...validCredential, date: 'abc\u202Edef\u200F\u061Cghi' };
      try {
        validateCredential(cred);
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg).not.toMatch(/\u202E/);
        expect(msg).not.toMatch(/\u200F/);
        expect(msg).not.toMatch(/\u061C/);
      }
    });
  });

  describe('year 0000 rejection', () => {
    it('rejects year 0000 as invalid date', () => {
      const cred = { ...validCredential, date: '0000-01-01' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 0000-01-01');
    });
  });

  describe('leap year handling', () => {
    it('accepts Feb 29 in a leap year (2024)', () => {
      const cred = { ...validCredential, date: '2024-02-29' };
      expect(validateCredential(cred)).toEqual(cred);
    });

    it('rejects Feb 29 in a non-leap year (2025)', () => {
      const cred = { ...validCredential, date: '2025-02-29' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2025-02-29');
    });

    it('accepts Feb 29 in a century leap year (2000)', () => {
      const cred = { ...validCredential, date: '2000-02-29' };
      expect(validateCredential(cred)).toEqual(cred);
    });

    it('rejects Feb 29 in a non-leap century year (1900)', () => {
      const cred = { ...validCredential, date: '1900-02-29' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 1900-02-29');
    });
  });

  describe('empty string fields', () => {
    for (const field of ['authority', 'date', 'honor', 'recipient'] as const) {
      it(`rejects empty ${field}`, () => {
        const cred = { ...validCredential, [field]: '' };
        expect(() => validateCredential(cred)).toThrow(
          `${field} must not be empty`,
        );
      });
    }
  });

  describe('whitespace in string fields', () => {
    it('rejects leading whitespace', () => {
      const cred = { ...validCredential, recipient: ' John' };
      expect(() => validateCredential(cred)).toThrow(
        'recipient must not have leading or trailing whitespace',
      );
    });

    it('rejects trailing whitespace', () => {
      const cred = { ...validCredential, recipient: 'John ' };
      expect(() => validateCredential(cred)).toThrow(
        'recipient must not have leading or trailing whitespace',
      );
    });

    it('rejects leading and trailing whitespace', () => {
      const cred = { ...validCredential, recipient: ' John ' };
      expect(() => validateCredential(cred)).toThrow(
        'recipient must not have leading or trailing whitespace',
      );
    });

    it('rejects whitespace in authority', () => {
      const cred = { ...validCredential, authority: ' HRH' };
      expect(() => validateCredential(cred)).toThrow(
        'authority must not have leading or trailing whitespace',
      );
    });
  });

  describe('wrong types for string fields', () => {
    for (const field of ['authority', 'date', 'honor', 'recipient'] as const) {
      it(`rejects ${field} as a number`, () => {
        const cred = { ...validCredential, [field]: 123 };
        expect(() => validateCredential(cred)).toThrow(
          `${field} must be a string`,
        );
      });
    }
  });

  describe('extra fields', () => {
    it('rejects an object with an extra field', () => {
      const cred = { ...validCredential, foo: 'bar' };
      expect(() => validateCredential(cred)).toThrow('unexpected field: foo');
    });

    it('rejects multiple extra fields (reports first encountered)', () => {
      const cred = { ...validCredential, aaa: 1, zzz: 2 };
      expect(() => validateCredential(cred)).toThrow(/unexpected field:/);
    });
  });
});
