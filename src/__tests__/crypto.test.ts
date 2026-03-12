import { describe, expect, it } from "vitest";

import { getPublicKey, sign, verify } from "../crypto.js";

describe("crypto", () => {
  // Helper: generate a keypair from a deterministic 32-byte seed.
  function makeKeypair(seed = 0) {
    const secretKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) secretKey[i] = (seed + i * 7) & 0xff;
    const publicKey = getPublicKey(secretKey);
    return { secretKey, publicKey };
  }

  // 1. Sign + verify round-trip with generated keypair
  it("sign + verify round-trip succeeds", () => {
    const { secretKey, publicKey } = makeKeypair();
    const message = new TextEncoder().encode("hello world");
    const signature = sign(message, secretKey);
    expect(verify(signature, message, publicKey)).toBe(true);
  });

  // 2. Tampered message → verify returns false
  it("rejects a tampered message", () => {
    const { secretKey, publicKey } = makeKeypair();
    const message = new TextEncoder().encode("original");
    const signature = sign(message, secretKey);
    const tampered = new TextEncoder().encode("modified");
    expect(verify(signature, tampered, publicKey)).toBe(false);
  });

  // 3. Tampered signature → verify returns false
  it("rejects a tampered signature", () => {
    const { secretKey, publicKey } = makeKeypair();
    const message = new TextEncoder().encode("test");
    const signature = sign(message, secretKey);
    const bad = new Uint8Array(signature);
    bad[0] ^= 0xff;
    expect(verify(bad, message, publicKey)).toBe(false);
  });

  // 4. Wrong public key → verify returns false
  it("rejects verification with wrong public key", () => {
    const { secretKey } = makeKeypair(0);
    const { publicKey: wrongKey } = makeKeypair(1);
    const message = new TextEncoder().encode("test");
    const signature = sign(message, secretKey);
    expect(verify(signature, message, wrongKey)).toBe(false);
  });

  // 5. Signature is exactly 64 bytes
  it("produces a 64-byte signature", () => {
    const { secretKey } = makeKeypair();
    const message = new TextEncoder().encode("test");
    const signature = sign(message, secretKey);
    expect(signature.length).toBe(64);
  });

  // 6. Public key is exactly 32 bytes
  it("produces a 32-byte public key", () => {
    const { publicKey } = makeKeypair();
    expect(publicKey.length).toBe(32);
  });

  // 7. Known RFC 8032 test vector (section 7.1 — empty message, 32-byte zero key)
  it("matches RFC 8032 section 7.1 test vector", () => {
    // Test vector 1 from RFC 8032 section 7.1:
    // SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    // PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3
    // MESSAGE: (empty)
    // SIGNATURE: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    const secretKey = hexToBytes(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const expectedPublicKey = hexToBytes(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    const expectedSignature = hexToBytes(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    const message = new Uint8Array(0);

    const publicKey = getPublicKey(secretKey);
    expect(publicKey).toEqual(expectedPublicKey);

    const signature = sign(message, secretKey);
    expect(signature).toEqual(expectedSignature);

    expect(verify(signature, message, publicKey)).toBe(true);
  });

  // 8. Empty message signs and verifies
  it("signs and verifies an empty message", () => {
    const { secretKey, publicKey } = makeKeypair();
    const empty = new Uint8Array(0);
    const signature = sign(empty, secretKey);
    expect(verify(signature, empty, publicKey)).toBe(true);
  });

  // 9. Wrong-length secret key → clear error
  describe("input validation", () => {
    it("sign rejects a 31-byte secret key", () => {
      const bad = new Uint8Array(31);
      const message = new Uint8Array(1);
      expect(() => sign(message, bad)).toThrow(
        "secretKey must be exactly 32 bytes, got 31",
      );
    });

    it("getPublicKey rejects a 31-byte secret key", () => {
      const bad = new Uint8Array(31);
      expect(() => getPublicKey(bad)).toThrow(
        "secretKey must be exactly 32 bytes, got 31",
      );
    });

    // 10. Wrong-length signature → clear error
    it("verify rejects a 63-byte signature", () => {
      const sig = new Uint8Array(63);
      const msg = new Uint8Array(1);
      const pk = new Uint8Array(32);
      expect(() => verify(sig, msg, pk)).toThrow(
        "signature must be exactly 64 bytes, got 63",
      );
    });

    // 11. Wrong-length public key → clear error
    it("verify rejects a 33-byte public key", () => {
      const sig = new Uint8Array(64);
      const msg = new Uint8Array(1);
      const pk = new Uint8Array(33);
      expect(() => verify(sig, msg, pk)).toThrow(
        "publicKey must be exactly 32 bytes, got 33",
      );
    });
  });
});

/** Convert a hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
