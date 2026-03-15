import { describe, expect, it } from 'vitest';
import {
  validateRegistry,
  isDateInRange,
  decodePublicKey,
  MAX_REGISTRY_KEYS,
} from '../registry.js';
import type { KeyEntry, Registry } from '../registry.js';

// A real Ed25519 SPKI DER public key (44 bytes base64 → 32 raw bytes after stripping prefix).
// Raw hex: d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3
// This is the well-known Ed25519 test vector for the empty-message key.
const SPKI_B64 = 'MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPao/ShiEawuNGD+OM=';
const RAW_32_HEX =
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18846b0b8d183f8e3';

// A raw 32-byte key as standard base64.
const RAW_B64 = '11qYAYKxCrfVS/7TyWQHOg7hcvPao/ShiEawuNGD+OM=';

function makeEntry(overrides: Partial<KeyEntry> = {}): KeyEntry {
  return {
    authority: 'HRH Prince Davit Bagrationi',
    from: '2025-01-01',
    to: '2026-12-31',
    algorithm: 'Ed25519',
    public_key: SPKI_B64,
    note: 'Primary signing key',
    ...overrides,
  };
}

function makeRegistry(
  entries: KeyEntry[] = [makeEntry()],
): { keys: KeyEntry[] } {
  return { keys: entries };
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// validateRegistry
// ---------------------------------------------------------------------------

describe('validateRegistry', () => {
  it('accepts a valid registry and returns it typed', () => {
    const input = makeRegistry();
    const result: Registry = validateRegistry(input);
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].authority).toBe('HRH Prince Davit Bagrationi');
  });

  it('accepts an entry with to: null', () => {
    const result = validateRegistry(makeRegistry([makeEntry({ to: null })]));
    expect(result.keys[0].to).toBeNull();
  });

  it('accepts an entry with an empty note', () => {
    const result = validateRegistry(makeRegistry([makeEntry({ note: '' })]));
    expect(result.keys[0].note).toBe('');
  });

  describe('rejects non-object inputs', () => {
    it('throws on null', () => {
      expect(() => validateRegistry(null)).toThrow(
        'registry must be a plain object',
      );
    });

    it('throws on an array', () => {
      expect(() => validateRegistry([])).toThrow(
        'registry must be a plain object',
      );
    });

    it('throws on a string', () => {
      expect(() => validateRegistry('hi')).toThrow(
        'registry must be a plain object',
      );
    });
  });

  it('throws when keys field is missing', () => {
    expect(() => validateRegistry({})).toThrow('missing required field: keys');
  });

  it('throws when keys is not an array', () => {
    expect(() => validateRegistry({ keys: 'nope' })).toThrow(
      'keys must be an array',
    );
  });

  it('throws when keys array is empty', () => {
    expect(() => validateRegistry({ keys: [] })).toThrow(
      'keys array must not be empty',
    );
  });

  it('rejects registry with more than MAX_REGISTRY_KEYS entries', () => {
    const entries = Array.from({ length: MAX_REGISTRY_KEYS + 1 }, () => makeEntry());
    expect(() => validateRegistry({ keys: entries })).toThrow('maximum key count');
  });

  it('accepts registry with exactly MAX_REGISTRY_KEYS entries', () => {
    const entries = Array.from({ length: MAX_REGISTRY_KEYS }, () => makeEntry());
    const result = validateRegistry({ keys: entries });
    expect(result.keys).toHaveLength(MAX_REGISTRY_KEYS);
  });

  it('rejects extra top-level fields', () => {
    const input = { keys: [makeEntry()], extra: true };
    expect(() => validateRegistry(input)).toThrow('unexpected field: extra');
  });

  describe('entry-level validation', () => {
    it('throws when an entry is not a plain object', () => {
      expect(() => validateRegistry({ keys: ['bad'] })).toThrow(
        'keys[0] must be a plain object',
      );
    });

    it('throws on extra fields in an entry', () => {
      const entry = { ...makeEntry(), extra: true };
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        'keys[0]: unexpected field: extra',
      );
    });

    describe('missing required fields', () => {
      for (const field of [
        'authority',
        'from',
        'to',
        'algorithm',
        'public_key',
        'note',
      ] as const) {
        it(`throws when ${field} is missing`, () => {
          const entry = makeEntry();
          delete (entry as Record<string, unknown>)[field];
          expect(() => validateRegistry({ keys: [entry] })).toThrow(
            `keys[0]: missing required field: ${field}`,
          );
        });
      }
    });

    describe('wrong types', () => {
      it('throws when authority is not a string', () => {
        const entry = { ...makeEntry(), authority: 123 };
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: authority must be a string',
        );
      });

      it('throws when from is not a string', () => {
        const entry = { ...makeEntry(), from: 123 };
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: from must be a string',
        );
      });

      it('throws when to is not a string or null', () => {
        const entry = { ...makeEntry(), to: 123 };
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: to must be a string or null',
        );
      });

      it('throws when public_key is not a string', () => {
        const entry = { ...makeEntry(), public_key: 42 };
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: public_key must be a string',
        );
      });

      it('throws when note is not a number instead of string', () => {
        const entry = { ...makeEntry(), note: 99 };
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: note must be a string',
        );
      });
    });

    it('throws when authority is empty', () => {
      const entry = makeEntry({ authority: '' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        'keys[0]: authority must not be empty',
      );
    });

    it('throws when public_key is empty', () => {
      const entry = makeEntry({ public_key: '' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        'keys[0]: public_key must not be empty',
      );
    });

    it('throws when algorithm is not Ed25519', () => {
      const entry = { ...makeEntry(), algorithm: 'RSA' };
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        "keys[0]: algorithm must be 'Ed25519'",
      );
    });

    describe('date validation on from/to', () => {
      it('rejects invalid from date (month 13)', () => {
        const entry = makeEntry({ from: '2025-13-01' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for from: 2025-13-01',
        );
      });

      it('rejects invalid from date (Feb 30)', () => {
        const entry = makeEntry({ from: '2025-02-30' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for from: 2025-02-30',
        );
      });

      it('rejects invalid to date (day 0)', () => {
        const entry = makeEntry({ to: '2026-01-00' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for to: 2026-01-00',
        );
      });

      it('rejects invalid to date (non-ISO format)', () => {
        const entry = makeEntry({ to: 'Dec 31, 2026' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for to: Dec 31, 2026',
        );
      });

      it('rejects Feb 29 in non-leap year for from', () => {
        const entry = makeEntry({ from: '2025-02-29' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for from: 2025-02-29',
        );
      });

      it('accepts Feb 29 in leap year for from', () => {
        const entry = makeEntry({ from: '2024-02-29' });
        const result = validateRegistry({ keys: [entry] });
        expect(result.keys[0].from).toBe('2024-02-29');
      });

      it('rejects month 0 for from', () => {
        const entry = makeEntry({ from: '2025-00-15' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for from: 2025-00-15',
        );
      });

      it('rejects April 31 for to', () => {
        const entry = makeEntry({ to: '2026-04-31' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for to: 2026-04-31',
        );
      });

      it('rejects year 0000 for from', () => {
        const entry = makeEntry({ from: '0000-01-01' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for from: 0000-01-01',
        );
      });

      it('rejects year 0000 for to', () => {
        const entry = makeEntry({ to: '0000-06-15' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'keys[0]: invalid date for to: 0000-06-15',
        );
      });

      it('rejects from after to (invalid date range)', () => {
        const entry = makeEntry({ from: '2025-06-01', to: '2025-01-01' });
        expect(() => validateRegistry({ keys: [entry] })).toThrow(
          'invalid date range',
        );
      });

      it('sanitizes bidi override characters in date error messages', () => {
        const entry = makeEntry({ from: '2025-01-01\u202E\u200F\u061C' });
        try {
          validateRegistry({ keys: [entry] });
        } catch (e) {
          const msg = (e as Error).message;
          expect(msg).not.toMatch(/\u202E/);
          expect(msg).not.toMatch(/\u200F/);
          expect(msg).not.toMatch(/\u061C/);
        }
      });
    });

    it('sanitizes control characters in from date error messages', () => {
      const entry = makeEntry({ from: '2025-01-01\x1b[31m' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        /invalid date for from/,
      );
      try {
        validateRegistry({ keys: [entry] });
      } catch (e) {
        expect((e as Error).message).not.toMatch(/\x1b/);
      }
    });

    it('sanitizes control characters in to date error messages', () => {
      const entry = makeEntry({ to: '2026-99-99\nINFO: fake' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        /invalid date for to/,
      );
      try {
        validateRegistry({ keys: [entry] });
      } catch (e) {
        expect((e as Error).message).not.toMatch(/\n/);
      }
    });

    it('rejects note with null byte control character', () => {
      const entry = makeEntry({ note: 'bad\u0000note' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        'keys[0]: note contains invalid control characters',
      );
    });

    it('rejects note with bidi override control character', () => {
      const entry = makeEntry({ note: 'bidi\u202eoverride' });
      expect(() => validateRegistry({ keys: [entry] })).toThrow(
        'keys[0]: note contains invalid control characters',
      );
    });

    it('reports the correct index for the second entry', () => {
      const good = makeEntry();
      const bad = { ...makeEntry(), algorithm: 'RSA' };
      expect(() => validateRegistry({ keys: [good, bad] })).toThrow(
        "keys[1]: algorithm must be 'Ed25519'",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// isDateInRange
// ---------------------------------------------------------------------------

describe('isDateInRange', () => {
  const key = makeEntry({ from: '2025-06-01', to: '2025-12-31' });

  it('returns true for a date within the range', () => {
    expect(isDateInRange('2025-08-15', key)).toBe(true);
  });

  it('returns true on the from boundary (inclusive)', () => {
    expect(isDateInRange('2025-06-01', key)).toBe(true);
  });

  it('returns true on the to boundary (inclusive)', () => {
    expect(isDateInRange('2025-12-31', key)).toBe(true);
  });

  it('returns false before the start', () => {
    expect(isDateInRange('2025-05-31', key)).toBe(false);
  });

  it('returns false after the end', () => {
    expect(isDateInRange('2026-01-01', key)).toBe(false);
  });

  it('returns true when to is null and date is after from', () => {
    const openKey = makeEntry({ from: '2025-01-01', to: null });
    expect(isDateInRange('2099-12-31', openKey)).toBe(true);
  });

  it('returns true when to is null and date equals from', () => {
    const openKey = makeEntry({ from: '2025-01-01', to: null });
    expect(isDateInRange('2025-01-01', openKey)).toBe(true);
  });

  it('returns false when to is null but date is before from', () => {
    const openKey = makeEntry({ from: '2025-01-01', to: null });
    expect(isDateInRange('2024-12-31', openKey)).toBe(false);
  });

  it('returns false for non-ISO-format date string', () => {
    const key = makeEntry({ from: '2025-01-01', to: '2025-12-31' });
    expect(isDateInRange('not-a-date', key)).toBe(false);
  });

  it('returns false for partial date string', () => {
    const key = makeEntry({ from: '2025-01-01', to: '2025-12-31' });
    expect(isDateInRange('2025-06', key)).toBe(false);
  });

  it('handles overlapping key periods — boundary date matches both', () => {
    const key1 = makeEntry({ from: '2025-01-01', to: '2025-06-30' });
    const key2 = makeEntry({ from: '2025-06-30', to: '2025-12-31' });
    const boundaryDate = '2025-06-30';

    expect(isDateInRange(boundaryDate, key1)).toBe(true);
    expect(isDateInRange(boundaryDate, key2)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// decodePublicKey
// ---------------------------------------------------------------------------

describe('decodePublicKey', () => {
  it('strips 12-byte SPKI header from 44-byte DER key', () => {
    const entry = makeEntry({ public_key: SPKI_B64 });
    const raw = decodePublicKey(entry);
    expect(raw).toHaveLength(32);
  });

  it('passes through a 32-byte raw key unchanged', () => {
    const entry = makeEntry({ public_key: RAW_B64 });
    const raw = decodePublicKey(entry);
    expect(raw).toHaveLength(32);
  });

  it('returns correct raw bytes from SPKI DER key (golden test)', () => {
    const entry = makeEntry({ public_key: SPKI_B64 });
    const raw = decodePublicKey(entry);
    const expected = hexToBytes(RAW_32_HEX);
    expect(raw).toEqual(expected);
  });

  it('throws on unexpected length (e.g., 48 bytes)', () => {
    // 48 bytes of zeros → base64
    const b64_48 = btoa(String.fromCharCode(...new Uint8Array(48)));
    const entry = makeEntry({ public_key: b64_48 });
    expect(() => decodePublicKey(entry)).toThrow(
      'decodePublicKey: unexpected key length 48 bytes (expected 32 or 44)',
    );
  });

  it('throws on 44-byte key with wrong SPKI prefix', () => {
    // 44 bytes but wrong prefix — flip first byte.
    const badPrefix = new Uint8Array(44);
    badPrefix[0] = 0xff;
    const b64 = btoa(String.fromCharCode(...badPrefix));
    const entry = makeEntry({ public_key: b64 });
    expect(() => decodePublicKey(entry)).toThrow(
      'decodePublicKey: 44-byte key does not have expected Ed25519 SPKI prefix',
    );
  });

  it('throws on empty decoded bytes (1-byte key)', () => {
    const b64 = btoa(String.fromCharCode(0x00));
    const entry = makeEntry({ public_key: b64 });
    expect(() => decodePublicKey(entry)).toThrow(
      'decodePublicKey: unexpected key length 1 bytes (expected 32 or 44)',
    );
  });
});
