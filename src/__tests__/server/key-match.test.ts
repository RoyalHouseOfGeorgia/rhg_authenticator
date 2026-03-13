import { describe, expect, it, vi, afterEach } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { findMatchingAuthority, isKeyActive } from '../../server/key-match.js';
import type { Registry, KeyEntry } from '../../registry.js';

// Deterministic 32-byte secret key for all tests.
const SECRET_KEY = new Uint8Array(32);
SECRET_KEY[0] = 0x01;
SECRET_KEY[31] = 0xff;

const PUBLIC_KEY = ed25519.getPublicKey(SECRET_KEY);
const PUBLIC_KEY_B64 = Buffer.from(PUBLIC_KEY).toString('base64');

const AUTHORITY = 'Royal House of Georgia';

function makeEntry(overrides?: Partial<KeyEntry>): KeyEntry {
  return {
    authority: AUTHORITY,
    from: '2020-01-01',
    to: null,
    algorithm: 'Ed25519',
    public_key: PUBLIC_KEY_B64,
    note: 'test key',
    ...overrides,
  };
}

function makeRegistry(entries: KeyEntry[]): Registry {
  return { keys: entries };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('findMatchingAuthority', () => {
  it('returns authority for a matching active key', () => {
    const registry = makeRegistry([makeEntry()]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBe(AUTHORITY);
  });

  it('returns undefined when public key does not match', () => {
    const otherSecret = new Uint8Array(32);
    otherSecret[0] = 0x02;
    otherSecret[31] = 0xfe;
    const otherPublicKey = ed25519.getPublicKey(otherSecret);
    const registry = makeRegistry([makeEntry()]);
    const result = findMatchingAuthority(registry, otherPublicKey, '2025-06-01');
    expect(result).toBeUndefined();
  });

  it('returns undefined when key is expired (to date in the past)', () => {
    const registry = makeRegistry([makeEntry({ to: '2024-12-31' })]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBeUndefined();
  });

  it('returns undefined when key from-date is in the future', () => {
    const registry = makeRegistry([makeEntry({ from: '2026-01-01' })]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBeUndefined();
  });

  it('silently skips entries with malformed public_key (invalid base64)', () => {
    const badEntry = makeEntry({ public_key: 'not-valid-base64!@#$' });
    const goodEntry = makeEntry({ authority: 'Good Authority' });
    const registry = makeRegistry([badEntry, goodEntry]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBe('Good Authority');
  });

  it('returns undefined when public key differs in last byte only (no false positive)', () => {
    // Create a key that differs only in the last byte.
    const almostKey = new Uint8Array(PUBLIC_KEY);
    almostKey[almostKey.length - 1] ^= 0x01;
    const registry = makeRegistry([makeEntry()]);
    const result = findMatchingAuthority(registry, almostKey, '2025-06-01');
    expect(result).toBeUndefined();
  });

  it('returns the first matching authority when multiple entries match', () => {
    const entry1 = makeEntry({ authority: 'First' });
    const entry2 = makeEntry({ authority: 'Second' });
    const registry = makeRegistry([entry1, entry2]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBe('First');
  });

  it('returns undefined for an empty keys array', () => {
    const registry = makeRegistry([]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBeUndefined();
  });

  it('matches when to is null (no upper bound)', () => {
    const registry = makeRegistry([makeEntry({ from: '2020-01-01', to: null })]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2099-12-31');
    expect(result).toBe(AUTHORITY);
  });

  it('matches on the exact from date (inclusive)', () => {
    const registry = makeRegistry([makeEntry({ from: '2025-06-01' })]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBe(AUTHORITY);
  });

  it('matches on the exact to date (inclusive)', () => {
    const registry = makeRegistry([makeEntry({ from: '2020-01-01', to: '2025-06-01' })]);
    const result = findMatchingAuthority(registry, PUBLIC_KEY, '2025-06-01');
    expect(result).toBe(AUTHORITY);
  });
});

describe('isKeyActive', () => {
  it('returns true for an active key with injected date', () => {
    const registry = makeRegistry([makeEntry()]);
    expect(isKeyActive(registry, PUBLIC_KEY, '2025-06-01')).toBe(true);
  });

  it('returns false for an expired key with injected date', () => {
    const registry = makeRegistry([makeEntry({ to: '2024-12-31' })]);
    expect(isKeyActive(registry, PUBLIC_KEY, '2025-06-01')).toBe(false);
  });

  it('uses today date when no date argument is provided', () => {
    // Key valid from 2020 with no upper bound — should match any "today".
    const registry = makeRegistry([makeEntry({ from: '2020-01-01', to: null })]);
    const result = isKeyActive(registry, PUBLIC_KEY);
    expect(result).toBe(true);
  });

  it('defaults to today and returns false for a future key', () => {
    const registry = makeRegistry([makeEntry({ from: '2099-01-01', to: null })]);
    const result = isKeyActive(registry, PUBLIC_KEY);
    expect(result).toBe(false);
  });
});
