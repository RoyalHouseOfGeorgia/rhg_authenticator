import { describe, expect, it } from 'vitest';
import {
  validateRevocationList,
  buildRevocationSet,
  isRevoked,
  MAX_REVOCATION_ENTRIES,
} from '../revocation.js';
import type { RevocationEntry, RevocationList } from '../revocation.js';

const VALID_HASH =
  'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const VALID_HASH_UPPER =
  'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90';
const VALID_DATE = '2026-03-15';

function makeEntry(overrides: Partial<RevocationEntry> = {}): RevocationEntry {
  return {
    hash: VALID_HASH,
    revoked_on: VALID_DATE,
    ...overrides,
  };
}

function makeList(
  entries: RevocationEntry[] = [makeEntry()],
): { revocations: RevocationEntry[] } {
  return { revocations: entries };
}

// ---------------------------------------------------------------------------
// validateRevocationList
// ---------------------------------------------------------------------------

describe('validateRevocationList', () => {
  it('accepts a valid revocation list and returns it typed', () => {
    const input = makeList();
    const result: RevocationList = validateRevocationList(input);
    expect(result.revocations).toHaveLength(1);
    expect(result.revocations[0].hash).toBe(VALID_HASH);
    expect(result.revocations[0].revoked_on).toBe(VALID_DATE);
  });

  it('accepts an empty revocations array', () => {
    const result = validateRevocationList({ revocations: [] });
    expect(result.revocations).toHaveLength(0);
  });

  it('accepts multiple valid entries', () => {
    const hash2 =
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const entries = [makeEntry(), makeEntry({ hash: hash2, revoked_on: '2026-01-01' })];
    const result = validateRevocationList(makeList(entries));
    expect(result.revocations).toHaveLength(2);
  });

  describe('rejects non-object inputs', () => {
    it('throws on null', () => {
      expect(() => validateRevocationList(null)).toThrow(
        'revocation list must be a plain object',
      );
    });

    it('throws on an array', () => {
      expect(() => validateRevocationList([])).toThrow(
        'revocation list must be a plain object',
      );
    });

    it('throws on a string', () => {
      expect(() => validateRevocationList('hi')).toThrow(
        'revocation list must be a plain object',
      );
    });

    it('throws on a number', () => {
      expect(() => validateRevocationList(42)).toThrow(
        'revocation list must be a plain object',
      );
    });

    it('throws on undefined', () => {
      expect(() => validateRevocationList(undefined)).toThrow(
        'revocation list must be a plain object',
      );
    });
  });

  it('throws when revocations field is missing', () => {
    expect(() => validateRevocationList({})).toThrow(
      'missing required field: revocations',
    );
  });

  it('throws when revocations is not an array', () => {
    expect(() => validateRevocationList({ revocations: 'nope' })).toThrow(
      'revocations must be an array',
    );
  });

  it('rejects list with more than MAX_REVOCATION_ENTRIES entries', () => {
    const entries = Array.from({ length: MAX_REVOCATION_ENTRIES + 1 }, (_, i) =>
      makeEntry({
        hash: i.toString(16).padStart(64, '0'),
      }),
    );
    expect(() => validateRevocationList({ revocations: entries })).toThrow(
      'maximum entry count',
    );
  });

  it('accepts list with exactly MAX_REVOCATION_ENTRIES entries', () => {
    const entries = Array.from({ length: MAX_REVOCATION_ENTRIES }, (_, i) =>
      makeEntry({
        hash: i.toString(16).padStart(64, '0'),
      }),
    );
    const result = validateRevocationList({ revocations: entries });
    expect(result.revocations).toHaveLength(MAX_REVOCATION_ENTRIES);
  });

  it('rejects extra top-level fields', () => {
    const input = { revocations: [makeEntry()], extra: true };
    expect(() => validateRevocationList(input)).toThrow(
      'unexpected field: extra',
    );
  });

  describe('entry-level validation', () => {
    it('throws when an entry is not a plain object', () => {
      expect(() => validateRevocationList({ revocations: ['bad'] })).toThrow(
        'revocations[0] must be a plain object',
      );
    });

    it('throws when an entry is null', () => {
      expect(() => validateRevocationList({ revocations: [null] })).toThrow(
        'revocations[0] must be a plain object',
      );
    });

    it('throws when an entry is an array', () => {
      expect(() => validateRevocationList({ revocations: [[]] })).toThrow(
        'revocations[0] must be a plain object',
      );
    });

    it('throws on extra fields in an entry', () => {
      const entry = { ...makeEntry(), extra: true };
      expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
        'revocations[0]: unexpected field: extra',
      );
    });

    describe('missing required fields', () => {
      it('throws when hash is missing', () => {
        const entry = { revoked_on: VALID_DATE };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: missing required field: hash',
        );
      });

      it('throws when revoked_on is missing', () => {
        const entry = { hash: VALID_HASH };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: missing required field: revoked_on',
        );
      });
    });

    describe('hash validation', () => {
      it('throws when hash is not a string', () => {
        const entry = { hash: 123, revoked_on: VALID_DATE };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: hash must be a string',
        );
      });

      it('throws when hash is too short', () => {
        const entry = { hash: 'abcd', revoked_on: VALID_DATE };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: hash must be a 64-character hex string',
        );
      });

      it('throws when hash is too long (65 chars)', () => {
        const entry = { hash: 'a'.repeat(65), revoked_on: VALID_DATE };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: hash must be a 64-character hex string',
        );
      });

      it('throws when hash contains non-hex characters', () => {
        const entry = {
          hash: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
          revoked_on: VALID_DATE,
        };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: hash must be a 64-character hex string',
        );
      });

      it('throws when hash is empty', () => {
        const entry = { hash: '', revoked_on: VALID_DATE };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: hash must be a 64-character hex string',
        );
      });
    });

    describe('revoked_on validation', () => {
      it('throws when revoked_on is not a string', () => {
        const entry = { hash: VALID_HASH, revoked_on: 20260315 };
        expect(() => validateRevocationList({ revocations: [entry] })).toThrow(
          'revocations[0]: revoked_on must be a string',
        );
      });

      it('throws on invalid date (month 13)', () => {
        const entry = makeEntry({ revoked_on: '2026-13-01' });
        expect(() =>
          validateRevocationList({ revocations: [entry] }),
        ).toThrow('revocations[0]: invalid date for revoked_on: 2026-13-01');
      });

      it('throws on invalid date (Feb 30)', () => {
        const entry = makeEntry({ revoked_on: '2026-02-30' });
        expect(() =>
          validateRevocationList({ revocations: [entry] }),
        ).toThrow('revocations[0]: invalid date for revoked_on: 2026-02-30');
      });

      it('throws on non-ISO format', () => {
        const entry = makeEntry({ revoked_on: 'March 15, 2026' });
        expect(() =>
          validateRevocationList({ revocations: [entry] }),
        ).toThrow(/revocations\[0\]: invalid date for revoked_on/);
      });

      it('throws on day 0', () => {
        const entry = makeEntry({ revoked_on: '2026-03-00' });
        expect(() =>
          validateRevocationList({ revocations: [entry] }),
        ).toThrow('revocations[0]: invalid date for revoked_on: 2026-03-00');
      });
    });

    it('reports the correct index for the second entry', () => {
      const good = makeEntry();
      const bad = { hash: 'short', revoked_on: VALID_DATE };
      expect(() =>
        validateRevocationList({ revocations: [good, bad] }),
      ).toThrow('revocations[1]: hash must be a 64-character hex string');
    });
  });

  describe('duplicate handling', () => {
    it('silently deduplicates entries with the same hash (keeps first)', () => {
      const entry1 = makeEntry({ revoked_on: '2026-01-01' });
      const entry2 = makeEntry({ revoked_on: '2026-06-15' });
      const result = validateRevocationList({
        revocations: [entry1, entry2],
      });
      expect(result.revocations).toHaveLength(1);
      expect(result.revocations[0].revoked_on).toBe('2026-01-01');
    });

    it('deduplicates across case differences', () => {
      const entry1 = makeEntry({ hash: VALID_HASH });
      const entry2 = makeEntry({ hash: VALID_HASH_UPPER, revoked_on: '2026-06-15' });
      const result = validateRevocationList({
        revocations: [entry1, entry2],
      });
      expect(result.revocations).toHaveLength(1);
    });

    it('keeps distinct hashes when mixed with duplicates', () => {
      const hash2 =
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const entries = [
        makeEntry(),
        makeEntry({ hash: hash2 }),
        makeEntry(), // duplicate of first
      ];
      const result = validateRevocationList({ revocations: entries });
      expect(result.revocations).toHaveLength(2);
    });
  });

  describe('case normalization', () => {
    it('normalizes uppercase hex hash to lowercase', () => {
      const entry = makeEntry({ hash: VALID_HASH_UPPER });
      const result = validateRevocationList({ revocations: [entry] });
      expect(result.revocations[0].hash).toBe(VALID_HASH);
    });

    it('normalizes mixed-case hex hash to lowercase', () => {
      const mixed =
        'A1b2C3d4E5f60718293a4B5c6D7e8F90a1B2c3D4e5F60718293A4b5C6d7E8f90';
      const result = validateRevocationList({
        revocations: [makeEntry({ hash: mixed })],
      });
      expect(result.revocations[0].hash).toBe(VALID_HASH);
    });
  });

  it('sanitizes control characters in hash error messages', () => {
    const malicious = 'a'.repeat(60) + '\x1b[31';
    const entry = { hash: malicious, revoked_on: VALID_DATE };
    try {
      validateRevocationList({ revocations: [entry] });
    } catch (e) {
      expect((e as Error).message).not.toMatch(/\x1b/);
    }
  });
});

// ---------------------------------------------------------------------------
// buildRevocationSet
// ---------------------------------------------------------------------------

describe('buildRevocationSet', () => {
  it('returns a Set containing all hashes from the list', () => {
    const hash2 =
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const list: RevocationList = {
      revocations: [makeEntry(), makeEntry({ hash: hash2 })],
    };
    const set = buildRevocationSet(list);
    expect(set.size).toBe(2);
    expect(set.has(VALID_HASH)).toBe(true);
    expect(set.has(hash2)).toBe(true);
  });

  it('returns an empty Set for an empty revocation list', () => {
    const list: RevocationList = { revocations: [] };
    const set = buildRevocationSet(list);
    expect(set.size).toBe(0);
  });

  it('finds hash at position MAX_REVOCATION_ENTRIES - 1 via set lookup', () => {
    const entries = Array.from({ length: MAX_REVOCATION_ENTRIES }, (_, i) =>
      makeEntry({ hash: i.toString(16).padStart(64, '0') }),
    );
    const list: RevocationList = { revocations: entries };
    const set = buildRevocationSet(list);
    expect(set.size).toBe(MAX_REVOCATION_ENTRIES);

    // The last entry's hash (index 9999).
    const lastHash = (MAX_REVOCATION_ENTRIES - 1).toString(16).padStart(64, '0');
    expect(set.has(lastHash)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isRevoked
// ---------------------------------------------------------------------------

describe('isRevoked', () => {
  const set = new Set([VALID_HASH]);

  it('returns true when hash is found (exact match)', () => {
    expect(isRevoked(VALID_HASH, set)).toBe(true);
  });

  it('returns false when hash is not found', () => {
    const other =
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    expect(isRevoked(other, set)).toBe(false);
  });

  it('is case insensitive (uppercase input matches lowercase set)', () => {
    expect(isRevoked(VALID_HASH_UPPER, set)).toBe(true);
  });

  it('is case insensitive (mixed case input matches lowercase set)', () => {
    const mixed =
      'A1b2C3d4E5f60718293a4B5c6D7e8F90a1B2c3D4e5F60718293A4b5C6d7E8f90';
    expect(isRevoked(mixed, set)).toBe(true);
  });

  it('returns false for empty set', () => {
    expect(isRevoked(VALID_HASH, new Set())).toBe(false);
  });
});
