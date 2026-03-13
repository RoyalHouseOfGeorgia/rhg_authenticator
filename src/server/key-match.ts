import { decodePublicKey, isDateInRange } from '../registry.js';
import type { Registry } from '../registry.js';

/**
 * Find the authority name for a key that matches the given public key
 * and is active on the given date. Returns undefined if no match.
 */
export function findMatchingAuthority(
  registry: Registry,
  publicKey: Uint8Array,
  date: string,
): string | undefined {
  for (const entry of registry.keys) {
    let decoded: Uint8Array;
    try {
      decoded = decodePublicKey(entry);
    } catch {
      continue;
    }
    // Not a security comparison (lookup, not authentication) — timing-safe
    // comparison is not required here. The public key is not a secret.
    if (
      decoded.length === publicKey.length &&
      decoded.every((b, i) => b === publicKey[i]) &&
      isDateInRange(date, entry)
    ) {
      return entry.authority;
    }
  }
  return undefined;
}

/**
 * Check whether a public key has an active entry in the registry.
 * Defaults to today's date in UTC. All date comparisons in this system
 * use UTC — callers in non-UTC timezones should be aware of the
 * ~1 day window near midnight.
 */
export function isKeyActive(
  registry: Registry,
  publicKey: Uint8Array,
  date?: string,
): boolean {
  const effectiveDate = date ?? new Date().toISOString().slice(0, 10);
  return findMatchingAuthority(registry, publicKey, effectiveDate) !== undefined;
}
