import { describe, expect, it } from 'vitest';
import {
  validateCredential,
  UnsupportedVersionError,
  sanitizeForError,
  CONTROL_CHAR_PATTERN,
} from '../credential.js';
import type { Credential } from '../credential.js';

const validCredential = {
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
    it.each([
      ['null', null],
      ['an array', [1, 2, 3]],
      ['a number', 42],
    ])('throws on %s', (_label, input) => {
      expect(() => validateCredential(input)).toThrow(
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
    it.each<{ name: string; version: unknown; message: string; errorClass?: typeof UnsupportedVersionError }>([
      {
        name: 'throws UnsupportedVersionError for version 2',
        version: 2,
        message: 'Unsupported credential version: 2',
        errorClass: UnsupportedVersionError,
      },
      {
        name: 'throws when version is a string instead of a number',
        version: '1',
        message: 'version must be a number',
      },
    ])('$name', ({ version, message, errorClass }) => {
      const cred = { ...validCredential, version };
      if (errorClass !== undefined) {
        expect(() => validateCredential(cred)).toThrow(errorClass);
      }
      expect(() => validateCredential(cred)).toThrow(message);
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

    it('has name set to UnsupportedVersionError', () => {
      const err = new UnsupportedVersionError(99);
      expect(err.name).toBe('UnsupportedVersionError');
    });
  });

  describe('date validation', () => {
    it('rejects February 30', () => {
      const cred = { ...validCredential, date: '2026-02-30' };
      expect(() => validateCredential(cred)).toThrow('invalid date: 2026-02-30');
    });

    it('rejects wrong format (natural language)', () => {
      const cred = { ...validCredential, date: 'Mar11,2026' };
      expect(() => validateCredential(cred)).toThrow(/invalid date/);
    });

  });

  describe('empty string fields', () => {
    for (const field of ['date', 'detail', 'honor', 'recipient'] as const) {
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

  });

  describe('wrong types for string fields', () => {
    for (const field of ['date', 'detail', 'honor', 'recipient'] as const) {
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

    it('rejects control characters in date', () => {
      const cred = { ...validCredential, date: '2026\x00-03-11' };
      expect(() => validateCredential(cred)).toThrow(
        'date contains invalid control characters',
      );
    });
  });

  describe('field max length limits', () => {
    it.each<{ name: string; field: string; value: string; rejects?: string }>([
      { name: 'accepts recipient at max length (500)', field: 'recipient', value: 'R'.repeat(500) },
      {
        name: 'rejects recipient one char over max (501)',
        field: 'recipient',
        value: 'R'.repeat(501),
        rejects: 'recipient exceeds maximum length of 500',
      },
      { name: 'accepts honor at max length (200)', field: 'honor', value: 'H'.repeat(200) },
      {
        name: 'rejects honor one char over max (201)',
        field: 'honor',
        value: 'H'.repeat(201),
        rejects: 'honor exceeds maximum length of 200',
      },
      { name: 'accepts detail at max length (2000)', field: 'detail', value: 'D'.repeat(2000) },
      {
        name: 'rejects detail one char over max (2001)',
        field: 'detail',
        value: 'D'.repeat(2001),
        rejects: 'detail exceeds maximum length of 2000',
      },
      {
        name: 'rejects date one char over max (11)',
        field: 'date',
        value: '2026-03-111',
        rejects: 'date exceeds maximum length of 10',
      },
    ])('$name', ({ field, value, rejects }) => {
      const cred = { ...validCredential, [field]: value };
      if (rejects === undefined) {
        expect(() => validateCredential(cred)).not.toThrow();
      } else {
        expect(() => validateCredential(cred)).toThrow(rejects);
      }
    });
  });

  describe('extra fields', () => {
    it('rejects an object with an extra field', () => {
      const cred = { ...validCredential, foo: 'bar' };
      expect(() => validateCredential(cred)).toThrow('unexpected field: foo');
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
