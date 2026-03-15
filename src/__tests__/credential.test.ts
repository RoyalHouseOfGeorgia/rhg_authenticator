import { describe, expect, it } from 'vitest';
import {
  validateCredential,
  UnsupportedVersionError,
  sanitizeForError,
  CONTROL_CHAR_PATTERN,
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
      const cred = { ...validCredential, date: 'Mar11,2026' };
      expect(() => validateCredential(cred)).toThrow(/invalid date/);
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
      expect(() => validateCredential(cred)).toThrow('date contains invalid control characters');
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
    for (const field of ['authority', 'date', 'detail', 'honor', 'recipient'] as const) {
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
    for (const field of ['authority', 'date', 'detail', 'honor', 'recipient'] as const) {
      it(`rejects ${field} as a number`, () => {
        const cred = { ...validCredential, [field]: 123 };
        expect(() => validateCredential(cred)).toThrow(
          `${field} must be a string`,
        );
      });
    }
  });

  describe('control character rejection', () => {
    it('rejects null byte (\\x00) in recipient', () => {
      const cred = { ...validCredential, recipient: 'John\x00Doe' };
      expect(() => validateCredential(cred)).toThrow(
        'recipient contains invalid control characters',
      );
    });

    it('rejects bidi override (\\u202e) in honor', () => {
      const cred = { ...validCredential, honor: 'Test\u202eHonor' };
      expect(() => validateCredential(cred)).toThrow(
        'honor contains invalid control characters',
      );
    });

    it('rejects tab (\\t) in detail', () => {
      const cred = { ...validCredential, detail: 'Test\tDetail' };
      expect(() => validateCredential(cred)).toThrow(
        'detail contains invalid control characters',
      );
    });

    it('rejects control characters in authority', () => {
      const cred = { ...validCredential, authority: 'Auth\x1fority' };
      expect(() => validateCredential(cred)).toThrow(
        'authority contains invalid control characters',
      );
    });

    it('rejects control characters in date', () => {
      const cred = { ...validCredential, date: '2026\x00-03-11' };
      expect(() => validateCredential(cred)).toThrow(
        'date contains invalid control characters',
      );
    });
  });

  describe('field max length limits', () => {
    it('accepts authority at max length (200)', () => {
      const cred = { ...validCredential, authority: 'A'.repeat(200) };
      expect(() => validateCredential(cred)).not.toThrow('exceeds maximum length');
    });

    it('rejects authority one char over max (201)', () => {
      const cred = { ...validCredential, authority: 'A'.repeat(201) };
      expect(() => validateCredential(cred)).toThrow(
        'authority exceeds maximum length of 200',
      );
    });

    it('accepts recipient at max length (500)', () => {
      const cred = { ...validCredential, recipient: 'R'.repeat(500) };
      expect(() => validateCredential(cred)).not.toThrow('exceeds maximum length');
    });

    it('rejects recipient one char over max (501)', () => {
      const cred = { ...validCredential, recipient: 'R'.repeat(501) };
      expect(() => validateCredential(cred)).toThrow(
        'recipient exceeds maximum length of 500',
      );
    });

    it('accepts honor at max length (200)', () => {
      const cred = { ...validCredential, honor: 'H'.repeat(200) };
      expect(() => validateCredential(cred)).not.toThrow('exceeds maximum length');
    });

    it('rejects honor one char over max (201)', () => {
      const cred = { ...validCredential, honor: 'H'.repeat(201) };
      expect(() => validateCredential(cred)).toThrow(
        'honor exceeds maximum length of 200',
      );
    });

    it('accepts detail at max length (2000)', () => {
      const cred = { ...validCredential, detail: 'D'.repeat(2000) };
      expect(() => validateCredential(cred)).not.toThrow('exceeds maximum length');
    });

    it('rejects detail one char over max (2001)', () => {
      const cred = { ...validCredential, detail: 'D'.repeat(2001) };
      expect(() => validateCredential(cred)).toThrow(
        'detail exceeds maximum length of 2000',
      );
    });

    it('accepts date at max length (10)', () => {
      const cred = { ...validCredential, date: '2026-03-11' };
      expect(cred.date.length).toBe(10);
      expect(() => validateCredential(cred)).not.toThrow('exceeds maximum length');
    });

    it('rejects date one char over max (11)', () => {
      const cred = { ...validCredential, date: '2026-03-111' };
      expect(() => validateCredential(cred)).toThrow(
        'date exceeds maximum length of 10',
      );
    });

    it('accepts authority with emoji near boundary (199 BMP + 1 emoji = 200 code points)', () => {
      // 199 BMP chars + 1 emoji (U+1F600, 2 UTF-16 code units) = .length 201 but [...s].length 200
      const value = 'A'.repeat(199) + '\u{1F600}';
      expect(value.length).toBe(201); // UTF-16 length
      expect([...value].length).toBe(200); // code point length
      const cred = { ...validCredential, authority: value };
      expect(() => validateCredential(cred)).not.toThrow();
    });

    it('rejects authority with emoji over boundary (200 BMP + 1 emoji = 201 code points)', () => {
      // 200 BMP chars + 1 emoji (U+1F600, 2 UTF-16 code units) = .length 202 but [...s].length 201
      const value = 'A'.repeat(200) + '\u{1F600}';
      expect(value.length).toBe(202); // UTF-16 length
      expect([...value].length).toBe(201); // code point length
      const cred = { ...validCredential, authority: value };
      expect(() => validateCredential(cred)).toThrow(
        'authority exceeds maximum length of 200',
      );
    });
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

describe('sanitizeForError', () => {
  it('strips C0 control characters', () => {
    expect(sanitizeForError('\x00hello\nworld\r\t!')).toBe('helloworld!');
  });

  it('strips C1 control characters', () => {
    expect(sanitizeForError('a\x80b\x9fc')).toBe('abc');
  });

  it('strips bidi override characters', () => {
    expect(sanitizeForError('a\u202Ab\u2069c\u200Ed\u200Fe\u061Cf')).toBe(
      'abcdef',
    );
  });

  it('preserves normal ASCII text and spaces', () => {
    const input = 'Hello, World! 123 @#$%^&*()';
    expect(sanitizeForError(input)).toBe(input);
  });

  it('preserves non-Latin characters', () => {
    const georgian = 'ქართველი';
    expect(sanitizeForError(georgian)).toBe(georgian);
  });

  it('handles 1MB+ string without crashing', () => {
    const big = 'a'.repeat(1_100_000);
    expect(sanitizeForError(big)).toBe(big);
  });

  it('returns empty string when input is empty', () => {
    expect(sanitizeForError('')).toBe('');
  });

  it('returns empty string when input is entirely control characters', () => {
    expect(sanitizeForError('\x00\x01\x1f\x7f\x80\x9f')).toBe('');
  });
});
