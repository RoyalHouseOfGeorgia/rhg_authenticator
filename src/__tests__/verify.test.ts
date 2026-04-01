import { describe, expect, it, vi } from "vitest";

import { createHash } from "crypto";
import { verifyCredential, MAX_PAYLOAD_BYTES } from "../verify.js";
import type {
  VerificationSuccess,
  VerificationFailure,
  VerificationRevoked,
  RevocationCheck,
} from "../verify.js";
import { sign } from "../crypto.js";
import { canonicalize } from "../canonical.js";
import { base64urlEncode, base64urlDecode } from "../base64url.js";
import type { KeyEntry } from "../registry.js";
import {
  makeKeypair,
  makeKeyEntry,
  makeRegistry,
  validCredentialObj,
} from "./helpers.js";

/** Encode a credential object to UTF-8 bytes (canonical JSON). */
function encodeCredential(cred: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(cred));
}

describe("verifyCredential", () => {
  // 1. Happy path
  it("returns valid with matching key and parsed credential", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const result = verifyCredential(payload, signature, registry);

    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(entry);
    expect(success.credential).toEqual({
      version: 1,
      recipient: "Jane Doe",
      honor: "Test Honor",
      detail: "Test Detail",
      date: "2024-06-15",
    });
  });

  // 2. Tampered payload
  it("rejects a tampered payload", () => {
    const { secretKey, publicKey } = makeKeypair();
    const payload = encodeCredential(validCredentialObj());
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    // Tamper: change the payload after signing
    const tampered = encodeCredential(
      validCredentialObj({ recipient: "Evil Eve" }),
    );
    const result = verifyCredential(tampered, signature, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain(
      "no matching key produced a valid signature",
    );
  });

  // 4. Tampered signature
  it("rejects a tampered signature", () => {
    const { secretKey, publicKey } = makeKeypair();
    const payload = encodeCredential(validCredentialObj());
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const badSig = new Uint8Array(signature);
    badSig[0] ^= 0xff;
    const result = verifyCredential(payload, badSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain(
      "no matching key produced a valid signature",
    );
  });

  // 5. Date before key's from
  it("returns date-mismatch failure when credential date is before key's from", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj({ date: "2019-06-15" });
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey, { from: "2020-01-01", to: null });
    const registry = makeRegistry(entry);

    const result = verifyCredential(payload, signature, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain(
      "credential date outside key validity period",
    );
  });

  // 6. Date after key's to
  it("returns date-mismatch failure when credential date is after key's to", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj({ date: "2025-06-15" });
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey, {
      from: "2020-01-01",
      to: "2024-12-31",
    });
    const registry = makeRegistry(entry);

    const result = verifyCredential(payload, signature, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain(
      "credential date outside key validity period",
    );
  });

  // 7. Key rotation: two keys, credentials in each period validate correctly
  it("handles key rotation — validates against correct era key", () => {
    const pair1 = makeKeypair(1);
    const pair2 = makeKeypair(2);

    const key1 = makeKeyEntry(pair1.publicKey, {
      from: "2020-01-01",
      to: "2023-12-31",
    });
    const key2 = makeKeyEntry(pair2.publicKey, {
      from: "2024-01-01",
      to: null,
    });
    const registry = makeRegistry(key1, key2);

    // Credential in era 1
    const cred1 = validCredentialObj({ date: "2022-06-15" });
    const payload1 = encodeCredential(cred1);
    const sig1 = sign(payload1, pair1.secretKey);
    const result1 = verifyCredential(payload1, sig1, registry);
    expect(result1.valid).toBe(true);
    const success1 = result1 as VerificationSuccess;
    expect(success1.key).toBe(key1);
    expect(success1.credential.date).toBe("2022-06-15");

    // Credential in era 2
    const cred2 = validCredentialObj({ date: "2024-06-15" });
    const payload2 = encodeCredential(cred2);
    const sig2 = sign(payload2, pair2.secretKey);
    const result2 = verifyCredential(payload2, sig2, registry);
    expect(result2.valid).toBe(true);
    const success2 = result2 as VerificationSuccess;
    expect(success2.key).toBe(key2);
    expect(success2.credential.date).toBe("2024-06-15");
  });

  // 8. No short-circuit: key A invalid sig, key B valid sig + wrong date, key C valid sig + right date → success with key C
  it("does not short-circuit — finds the correct key among multiple candidates", () => {
    const pairA = makeKeypair(10);
    const pairB = makeKeypair(20);
    const pairC = makeKeypair(30);

    const cred = validCredentialObj({ date: "2024-06-15" });
    const payload = encodeCredential(cred);
    const signature = sign(payload, pairC.secretKey);

    // Key A: right date range, wrong key (doesn't match signature)
    const keyA = makeKeyEntry(pairA.publicKey, {
      from: "2020-01-01",
      to: null,
    });
    // Key B: wrong date range, correct key (matches signature but date out)
    const keyB = makeKeyEntry(pairC.publicKey, {
      from: "2020-01-01",
      to: "2023-12-31",
      note: "keyB uses pairC pubkey but restricted dates",
    });
    // Key C: right date range, correct key
    const keyC = makeKeyEntry(pairC.publicKey, {
      from: "2024-01-01",
      to: null,
      note: "keyC correct",
    });
    const registry = makeRegistry(keyA, keyB, keyC);

    const result = verifyCredential(payload, signature, registry);
    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(keyC);
    expect(success.credential.date).toBe("2024-06-15");
    expect(success.credential.recipient).toBe("Jane Doe");
  });

  // 9. Invalid payload (not valid JSON)
  it("returns failure for invalid UTF-8 / bad JSON payload", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const badPayload = new Uint8Array([0xff, 0xfe, 0x00, 0x01]);
    const fakeSig = new Uint8Array(64);

    const result = verifyCredential(badPayload, fakeSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain("JSON");
  });

  // 10. Malformed credential (missing fields)
  it("returns failure for credential with missing fields", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const payload = encodeCredential({ version: 1 });
    const fakeSig = new Uint8Array(64);

    const result = verifyCredential(payload, fakeSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toBe(
      "credential validation failed",
    );
  });

  // 11. Unrecognized version
  it("returns specific failure for unsupported credential version", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const payload = encodeCredential({
      date: "2024-06-15",
      detail: "Test Detail",
      honor: "Test Honor",
      recipient: "Jane Doe",
      version: 99,
    });
    const fakeSig = new Uint8Array(64);

    const result = verifyCredential(payload, fakeSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain(
      "version not supported",
    );
  });

  // 12. JSON primitive payload (string, number, array)
  it("returns failure for JSON primitive payloads", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);
    const fakeSig = new Uint8Array(64);

    for (const primitive of ['"hello"', "42", "[1,2,3]", "null", "true"]) {
      const payload = new TextEncoder().encode(primitive);
      const result = verifyCredential(payload, fakeSig, registry);
      expect(result.valid).toBe(false);
      expect((result as VerificationFailure).reason).toContain(
        "must be a JSON object",
      );
    }
  });

  // 13. Corrupted registry key — skips bad key, continues to valid one
  it("skips corrupted registry key and continues to valid key", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);

    // Corrupted key entry (invalid base64 that decodes to wrong length)
    const corruptedEntry: KeyEntry = {
      authority: "Test Authority",
      from: "2020-01-01",
      to: null,
      algorithm: "Ed25519",
      public_key: btoa("short"), // 5 bytes, neither 32 nor 44
      note: "corrupted",
    };
    const goodEntry = makeKeyEntry(publicKey);
    const registry = makeRegistry(corruptedEntry, goodEntry);

    const result = verifyCredential(payload, signature, registry);
    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(goodEntry);
    expect(success.credential.recipient).toBe("Jane Doe");
  });

  // 13b. No console.warn on corrupted registry key (decodeFailures counter tracks it silently)
  it("does not emit console.warn when encountering a malformed key", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);

    const corruptedEntry: KeyEntry = {
      authority: "Test Authority",
      from: "2020-01-01",
      to: null,
      algorithm: "Ed25519",
      public_key: btoa("short"),
      note: "corrupted",
    };
    const goodEntry = makeKeyEntry(publicKey);
    const registry = makeRegistry(corruptedEntry, goodEntry);

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const result = verifyCredential(payload, signature, registry);
      expect(result.valid).toBe(true);
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });

  // 13c. No console.warn on malformed key at any position in single pass
  it("does not emit console.warn for malformed key regardless of position", () => {
    const { publicKey } = makeKeypair();
    const cred = validCredentialObj({ date: "2024-06-15" });
    const payload = encodeCredential(cred);
    const fakeSig = new Uint8Array(64);

    // Key at index 0: valid key, date-eligible
    const goodEntry = makeKeyEntry(publicKey, {
      from: "2020-01-01",
      to: null,
    });
    // Key at index 1: corrupted, date-ineligible — still encountered in single pass
    const corruptedEntry: KeyEntry = {
      authority: "Test Authority",
      from: "2000-01-01",
      to: "2000-12-31",
      algorithm: "Ed25519",
      public_key: btoa("short"),
      note: "corrupted",
    };
    const registry = makeRegistry(goodEntry, corruptedEntry);

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      verifyCredential(payload, fakeSig, registry);
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });

  // 14. End-to-end round-trip: canonicalize → sign → base64url → decode → verify
  it("end-to-end round-trip: canonicalize → sign → encode → decode → verify", () => {
    const { secretKey, publicKey } = makeKeypair(42);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const credential = validCredentialObj();
    const payloadBytes = canonicalize(
      credential as Record<string, string | number>,
    );
    const signatureBytes = sign(payloadBytes, secretKey);

    // Simulate URL transport: base64url encode then decode
    const payloadB64 = base64urlEncode(payloadBytes);
    const signatureB64 = base64urlEncode(signatureBytes);

    const decodedPayload = base64urlDecode(payloadB64);
    const decodedSignature = base64urlDecode(signatureB64);

    const result = verifyCredential(decodedPayload, decodedSignature, registry);
    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(entry);
    expect(success.credential).toEqual({
      version: 1,
      recipient: "Jane Doe",
      honor: "Test Honor",
      detail: "Test Detail",
      date: "2024-06-15",
    });
  });

  // 15. Payload exceeds maximum size
  it("rejects payload exceeding MAX_PAYLOAD_BYTES", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);
    const fakeSig = new Uint8Array(64);

    const oversized = new Uint8Array(MAX_PAYLOAD_BYTES + 1);
    const result = verifyCredential(oversized, fakeSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain("maximum size");
  });

  // 16. Payload of exactly MAX_PAYLOAD_BYTES proceeds to normal validation
  it("accepts payload of exactly MAX_PAYLOAD_BYTES (size check does not fire)", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);
    const fakeSig = new Uint8Array(64);

    // Build a JSON object padded with trailing spaces to exactly MAX_PAYLOAD_BYTES.
    const base = '{"version":1}';
    const padding = " ".repeat(MAX_PAYLOAD_BYTES - base.length);
    const padded = base + padding;
    expect(padded.length).toBe(MAX_PAYLOAD_BYTES);

    const payload = new TextEncoder().encode(padded);
    const result = verifyCredential(payload, fakeSig, registry);

    expect(result.valid).toBe(false);
    // Should fail on credential validation, NOT on size.
    expect((result as VerificationFailure).reason).not.toContain("maximum size");
  });

  // 17. Oversized non-object payload — size check fires before type check
  it("rejects oversized non-object payload with size error, not type error", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);
    const fakeSig = new Uint8Array(64);

    // A JSON string that exceeds the size limit.
    const jsonString = '"' + "a".repeat(2047) + '"';
    const payload = new TextEncoder().encode(jsonString);
    expect(payload.length).toBeGreaterThan(MAX_PAYLOAD_BYTES);

    const result = verifyCredential(payload, fakeSig, registry);

    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toContain("maximum size");
    expect((result as VerificationFailure).reason).not.toContain(
      "must be a JSON object",
    );
  });

  // 18. Invalid curve point key (32 zero bytes) — first-pass try/catch handles it
  it("skips key with invalid curve point (32 zero bytes) and verifies with good key", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);

    // 32 zero bytes: valid length so decodePublicKey accepts it, but invalid curve point
    const zeroKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(32)));
    const badEntry: KeyEntry = {
      authority: "Test Authority",
      from: "2020-01-01",
      to: null,
      algorithm: "Ed25519",
      public_key: zeroKeyBase64,
      note: "invalid curve point",
    };
    const goodEntry = makeKeyEntry(publicKey);
    const registry = makeRegistry(badEntry, goodEntry);

    const result = verifyCredential(payload, signature, registry);
    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(goodEntry);
    expect(success.credential.recipient).toBe("Jane Doe");
  });

  // 18b. console.warn is emitted when ed25519Verify throws unexpectedly
  it("emits console.warn and continues when ed25519Verify throws unexpectedly", async () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);

    // A key whose public-key bytes decode successfully (valid length) but will
    // cause ed25519Verify to throw because we mock the verify function to throw
    // for that specific key.
    const throwingEntry = makeKeyEntry(publicKey, { note: "throws on verify" });
    const registry = makeRegistry(throwingEntry);

    const cryptoModule = await import("../crypto.js");
    const verifySpy = vi
      .spyOn(cryptoModule, "verify")
      .mockImplementationOnce(() => {
        throw new Error("unexpected internal error");
      });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const result = verifyCredential(payload, signature, registry);
      // The mocked throw should have been caught; no key matched, so we get a failure.
      expect(result.valid).toBe(false);
      expect((result as VerificationFailure).reason).toBe(
        "no matching key produced a valid signature",
      );
      // console.warn must have been called with the expected message prefix.
      expect(warnSpy).toHaveBeenCalledOnce();
      expect(warnSpy.mock.calls[0][0]).toBe(
        "Unexpected error during signature verification:",
      );
      expect(warnSpy.mock.calls[0][1]).toBeInstanceOf(Error);
    } finally {
      verifySpy.mockRestore();
      warnSpy.mockRestore();
    }
  });

  // 19. All registry keys fail to decode
  it("returns specific failure when all registry keys fail to decode", () => {
    const { secretKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);

    const badEntry1: KeyEntry = {
      authority: "Test Authority",
      from: "2020-01-01",
      to: null,
      algorithm: "Ed25519",
      public_key: "not-valid-base64!@#$",
      note: "corrupted key 1",
    };
    const badEntry2: KeyEntry = {
      authority: "Test Authority",
      from: "2020-01-01",
      to: null,
      algorithm: "Ed25519",
      public_key: "also-not-valid!@#$%^",
      note: "corrupted key 2",
    };
    const registry = makeRegistry(badEntry1, badEntry2);

    const result = verifyCredential(payload, signature, registry);
    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toBe(
      "all registry keys failed to decode",
    );
  });

  // 20. URL byte-budget test
  it("max-length realistic credential fits within URL byte budget", () => {
    const { secretKey, publicKey } = makeKeypair(99);
    const entry = makeKeyEntry(publicKey, { authority: "თბილისის უნივერსიტეტი" });
    const registry = makeRegistry(entry);

    // Georgian names sized to approach but stay within the byte budget
    const credential = {
      date: "2024-12-31",
      detail: "დეტალი",
      honor: "წარჩინებით",
      recipient: "გიორგი მა",
      version: 1 as const,
    };

    const payloadBytes = canonicalize(
      credential as unknown as Record<string, string | number>,
    );
    const signatureBytes = sign(payloadBytes, secretKey);

    const payloadB64 = base64urlEncode(payloadBytes);
    const signatureB64 = base64urlEncode(signatureBytes);

    // Verify it actually verifies
    const result = verifyCredential(
      base64urlDecode(payloadB64),
      base64urlDecode(signatureB64),
      registry,
    );
    expect(result.valid).toBe(true);

    // Build a realistic URL
    const url = `https://example.edu/verify?p=${payloadB64}&s=${signatureB64}`;
    expect(url.length).toBeLessThanOrEqual(420);
    expect(payloadB64.length).toBeLessThanOrEqual(300);
  });

  it('rejects invalid signature length (32 bytes instead of 64)', () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const reg = makeRegistry(entry);
    const payload = canonicalize(validCredentialObj() as Record<string, string | number>);
    const shortSig = new Uint8Array(32);
    const result = verifyCredential(payload, shortSig, reg);
    expect(result.valid).toBe(false);
    expect((result as VerificationFailure).reason).toBe('invalid signature length');
  });

  it("returns failure for empty registry (no keys)", () => {
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const fakeSig = new Uint8Array(64);
    const registry = makeRegistry(); // no keys

    const result = verifyCredential(payload, fakeSig, registry);

    expect(result.valid).toBe(false);
    const failure = result as VerificationFailure;
    expect(failure.revoked).toBe(false);
    expect(failure.reason).toBe("registry contains no keys");
  });
});

/** Compute SHA-256 hex digest of a Uint8Array. */
function sha256hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

describe("verifyCredential — revocation checks", () => {
  it("returns valid when no revocation param is provided (backwards compat)", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const result = verifyCredential(payload, signature, registry);

    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(entry);
  });

  it("returns revoked result for a valid credential that is in the revocation set", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const hash = sha256hex(payload);
    const revocation: RevocationCheck = {
      revocationSet: new Set([hash]),
      payloadHash: hash,
    };

    const result = verifyCredential(payload, signature, registry, revocation);

    expect(result.valid).toBe(false);
    const revoked = result as VerificationRevoked;
    expect(revoked.revoked).toBe(true);
    expect(revoked.reason).toContain("revoked");
  });

  it("returns non-revoked failure when signature is invalid even if hash is in revocation set", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    // Tamper with the signature
    const badSig = new Uint8Array(signature);
    badSig[0] ^= 0xff;

    const hash = sha256hex(payload);
    const revocation: RevocationCheck = {
      revocationSet: new Set([hash]),
      payloadHash: hash,
    };

    const result = verifyCredential(payload, badSig, registry, revocation);

    expect(result.valid).toBe(false);
    const failure = result as VerificationFailure;
    expect(failure.revoked).toBe(false);
    expect(failure.reason).toContain("no matching key produced a valid signature");
  });

  it("returns valid when revocation set is empty", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const hash = sha256hex(payload);
    const revocation: RevocationCheck = {
      revocationSet: new Set(),
      payloadHash: hash,
    };

    const result = verifyCredential(payload, signature, registry, revocation);

    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(entry);
  });

  it("revocation result has revoked: true discriminant", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const hash = sha256hex(payload);
    const revocation: RevocationCheck = {
      revocationSet: new Set([hash, "other-hash-1", "other-hash-2"]),
      payloadHash: hash,
    };

    const result = verifyCredential(payload, signature, registry, revocation);

    expect(result.valid).toBe(false);
    // Type narrowing: check the discriminant
    if (!result.valid) {
      expect("revoked" in result).toBe(true);
      if ("revoked" in result && result.revoked) {
        expect(result.revoked).toBe(true);
        expect(result.reason).toBe("this credential has been revoked");
      }
    }
  });

  it("returns revoked (not date-invalid) when signature matches an expired key", () => {
    const { secretKey, publicKey } = makeKeypair();
    // Key expired end of 2023; credential date is mid-2024 (outside range).
    const cred = validCredentialObj({ date: "2024-06-15" });
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey, {
      from: "2020-01-01",
      to: "2023-12-31",
    });
    const registry = makeRegistry(entry);

    const hash = sha256hex(payload);
    const revocation: RevocationCheck = {
      revocationSet: new Set([hash]),
      payloadHash: hash,
    };

    const result = verifyCredential(payload, signature, registry, revocation);

    expect(result.valid).toBe(false);
    const revoked = result as VerificationRevoked;
    expect(revoked.revoked).toBe(true);
    expect(revoked.reason).toContain("revoked");
  });

  it("returns valid when revocation set contains a different hash (mismatched payloadHash)", () => {
    const { secretKey, publicKey } = makeKeypair();
    const cred = validCredentialObj();
    const payload = encodeCredential(cred);
    const signature = sign(payload, secretKey);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const realHash = sha256hex(payload);
    const otherHash = createHash("sha256").update("something-else").digest("hex");
    const revocation: RevocationCheck = {
      revocationSet: new Set([otherHash]),
      payloadHash: realHash,
    };

    const result = verifyCredential(payload, signature, registry, revocation);

    expect(result.valid).toBe(true);
    const success = result as VerificationSuccess;
    expect(success.key).toBe(entry);
  });

  it("existing failure results include revoked: false discriminant", () => {
    const { publicKey } = makeKeypair();
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    // Trigger the "payload is not valid JSON" path
    const badPayload = new Uint8Array([0xff, 0xfe, 0x00, 0x01]);
    const fakeSig = new Uint8Array(64);
    const result = verifyCredential(badPayload, fakeSig, registry);

    expect(result.valid).toBe(false);
    const failure = result as VerificationFailure;
    expect(failure.revoked).toBe(false);
    expect(failure.reason).toContain("JSON");
  });
});
