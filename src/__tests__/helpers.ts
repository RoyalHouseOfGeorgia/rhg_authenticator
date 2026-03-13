import { getPublicKey } from "../crypto.js";
import type { KeyEntry, Registry } from "../registry.js";

/** Generate a deterministic Ed25519 keypair from a seed byte. */
export function makeKeypair(seed = 0) {
  const secretKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) secretKey[i] = (seed + i * 7) & 0xff;
  const publicKey = getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/** Encode raw 32-byte public key as standard base64. */
export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** Build a KeyEntry for tests. */
export function makeKeyEntry(
  publicKey: Uint8Array,
  opts: {
    authority?: string;
    from?: string;
    to?: string | null;
    note?: string;
  } = {},
): KeyEntry {
  return {
    authority: opts.authority ?? "Test Authority",
    from: opts.from ?? "2020-01-01",
    to: opts.to !== undefined ? opts.to : null,
    algorithm: "Ed25519",
    public_key: toBase64(publicKey),
    note: opts.note ?? "",
  };
}

/** Build a Registry from key entries. */
export function makeRegistry(...keys: KeyEntry[]): Registry {
  return { keys };
}

/** Default valid credential fields. */
export function validCredentialObj(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    authority: "Test Authority",
    date: "2024-06-15",
    detail: "Test Detail",
    honor: "Test Honor",
    recipient: "Jane Doe",
    version: 1,
    ...overrides,
  };
}
