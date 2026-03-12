import { describe, expect, it } from "vitest";

import {
  base64Decode,
  base64urlDecode,
  base64urlEncode,
  MAX_B64URL_INPUT,
  MAX_B64_INPUT,
} from "../base64url.js";

describe("base64url", () => {
  // 1. Empty input round-trips
  it("round-trips empty input", () => {
    const empty = new Uint8Array(0);
    const encoded = base64urlEncode(empty);
    expect(encoded).toBe("");
    expect(base64urlDecode(encoded)).toEqual(empty);
  });

  // 2. Known vector: "Hello" → SGVsbG8
  it('encodes "Hello" bytes to SGVsbG8', () => {
    const bytes = new TextEncoder().encode("Hello");
    expect(base64urlEncode(bytes)).toBe("SGVsbG8");
  });

  it('decodes SGVsbG8 back to "Hello" bytes', () => {
    const expected = new TextEncoder().encode("Hello");
    expect(base64urlDecode("SGVsbG8")).toEqual(expected);
  });

  // 3. Parameterized round-trips for lengths 0–6 (all mod-3 remainder classes)
  describe("round-trips for byte lengths 0 through 6", () => {
    for (let len = 0; len <= 6; len++) {
      it(`length ${len}`, () => {
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 13) & 0xff;
        const encoded = base64urlEncode(bytes);
        expect(base64urlDecode(encoded)).toEqual(bytes);
      });
    }
  });

  // 4. Large payload round-trip (~500 bytes)
  it("round-trips a 500-byte payload", () => {
    const bytes = new Uint8Array(500);
    for (let i = 0; i < 500; i++) bytes[i] = (i * 7 + 3) & 0xff;
    const encoded = base64urlEncode(bytes);
    expect(base64urlDecode(encoded)).toEqual(bytes);
  });

  // 5. Standard Base64 decode of a known Ed25519 SPKI DER key
  describe("base64Decode", () => {
    it("decodes a 44-byte Ed25519 SPKI DER key", () => {
      const b64 =
        "MCowBQYDK2VwAyEAGb1gauf9XRYSbnD0HkeUN5GNVMnFP+MYBmWBSAxPOVQ=";
      const decoded = base64Decode(b64);
      expect(decoded.length).toBe(44);

      // First 12 bytes are the SPKI header for Ed25519
      const header = decoded.slice(0, 12);
      expect(header).toEqual(
        new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
      );
    });

    it("throws on invalid characters", () => {
      expect(() => base64Decode("not valid!")).toThrow("base64Decode: invalid Base64 input");
    });
  });

  // 6. Handles padded and unpadded Base64URL input identically
  it("decodes padded and unpadded Base64URL to the same result", () => {
    const padded = "SGVsbG8=";
    const unpadded = "SGVsbG8";
    expect(base64urlDecode(padded)).toEqual(base64urlDecode(unpadded));
  });

  // 7. Throws on invalid characters
  describe("throws on invalid characters", () => {
    const invalidInputs = ["abc#def", "abc!def", "abc def"];
    for (const input of invalidInputs) {
      it(`rejects "${input}"`, () => {
        expect(() => base64urlDecode(input)).toThrow(
          "base64urlDecode: invalid Base64URL input",
        );
      });
    }
  });

  // 8. Bytes producing + and / in standard Base64 use - and _ in Base64URL
  it("uses - and _ instead of + and / for URL-safe encoding", () => {
    // 0xFB, 0xEF, 0xBE → standard Base64 "+++++", actually "u++/" pattern
    // Specifically: bytes [0x3E, 0x3F] → standard b64 has + and /
    // Let's use bytes that produce known +/ in standard base64.
    // 0xFB = 251, 0xFF = 255, 0xBF = 191 → btoa gives "+/+/" patterns
    const bytes = new Uint8Array([0xfb, 0xef, 0xbe]);
    // Standard Base64 of these bytes: btoa("\xfb\xef\xbe") = "u+++"
    // Actually let's just verify the output doesn't contain + or /
    const encoded = base64urlEncode(bytes);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).toContain("-"); // must have URL-safe replacements

    // Verify round-trip
    expect(base64urlDecode(encoded)).toEqual(bytes);

    // Also try bytes that produce / in standard Base64
    const bytes2 = new Uint8Array([0x3f, 0xff, 0xff]);
    const encoded2 = base64urlEncode(bytes2);
    expect(encoded2).not.toContain("+");
    expect(encoded2).not.toContain("/");
    expect(encoded2).toContain("_"); // must have _ replacement for /
    expect(base64urlDecode(encoded2)).toEqual(bytes2);
  });

  // 10. Rejects remainder-1 lengths (invalid Base64URL)
  describe("throws on remainder-1 length input", () => {
    it('rejects "A" (length 1, remainder 1)', () => {
      expect(() => base64urlDecode("A")).toThrow(
        "base64urlDecode: invalid Base64URL input — invalid length",
      );
    });

    it('rejects "AAAAA" (length 5, remainder 1)', () => {
      expect(() => base64urlDecode("AAAAA")).toThrow(
        "base64urlDecode: invalid Base64URL input — invalid length",
      );
    });
  });

  // Pre-decode length limit checks
  describe("pre-decode length limits", () => {
    it("base64urlDecode throws when input exceeds MAX_B64URL_INPUT", () => {
      const longStr = "A".repeat(MAX_B64URL_INPUT + 1);
      expect(() => base64urlDecode(longStr)).toThrow(
        "input exceeds maximum length",
      );
    });

    it("base64urlDecode accepts input at exactly MAX_B64URL_INPUT length", () => {
      // Build a valid base64url string of exactly MAX_B64URL_INPUT chars
      // This will be valid base64url (all 'A's decode fine)
      const str = "A".repeat(MAX_B64URL_INPUT);
      // Should not throw the length error (may throw for other reasons but not length)
      expect(() => base64urlDecode(str)).not.toThrow(
        "input exceeds maximum length",
      );
    });

    it("base64Decode throws when input exceeds MAX_B64_INPUT", () => {
      const longStr = "A".repeat(MAX_B64_INPUT + 1);
      expect(() => base64Decode(longStr)).toThrow(
        "input exceeds maximum length",
      );
    });

    it("base64Decode accepts input at exactly MAX_B64_INPUT length", () => {
      const str = "A".repeat(MAX_B64_INPUT);
      expect(() => base64Decode(str)).not.toThrow(
        "input exceeds maximum length",
      );
    });
  });

  // 9. High-bit bytes exercise Latin-1 boundary
  it("correctly handles high-bit bytes (0x00, 0x7F, 0x80, 0xFF)", () => {
    const bytes = new Uint8Array([0x00, 0x7f, 0x80, 0xff]);
    const encoded = base64urlEncode(bytes);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(bytes);
  });
});
