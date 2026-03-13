/**
 * Base64URL and standard Base64 encoding/decoding utilities.
 *
 * Uses `btoa`/`atob` (available since Node 16) with character replacement
 * for URL-safety. Handles padded and unpadded input.
 */

/** Encode a Uint8Array to a Base64URL string (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  const binStr = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  const b64 = btoa(binStr);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Max base64url input length. Derived: ceil(MAX_PAYLOAD_BYTES × 4/3) = ceil(2730.67) = 2731. */
export const MAX_B64URL_INPUT = 2731;

/** Decode a Base64URL string (padded or unpadded) to a Uint8Array. */
export function base64urlDecode(str: string): Uint8Array {
  if (str.length > MAX_B64URL_INPUT) throw new Error('input exceeds maximum length');
  // Convert URL-safe alphabet back to standard Base64
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");

  // Restore padding
  const remainder = b64.length % 4;
  if (remainder === 1) {
    throw new Error(
      "base64urlDecode: invalid Base64URL input — invalid length",
    );
  }
  if (remainder === 2) b64 += "==";
  else if (remainder === 3) b64 += "=";

  let binStr: string;
  try {
    binStr = atob(b64);
  } catch (e) {
    throw new Error(
      `base64urlDecode: invalid Base64URL input — ${(e as Error).message}`,
    );
  }
  return Uint8Array.from(binStr, (c) => c.charCodeAt(0));
}

/** Maximum standard Base64 input length — generous limit for Ed25519 SPKI keys (valid keys are <=60 chars). */
export const MAX_B64_INPUT = 256;

/** Decode a standard Base64 string (padded) to a Uint8Array. */
export function base64Decode(str: string): Uint8Array {
  if (str.length > MAX_B64_INPUT) throw new Error('input exceeds maximum length');
  let binStr: string;
  try {
    binStr = atob(str);
  } catch (e) {
    throw new Error(
      `base64Decode: invalid Base64 input — ${(e as Error).message}`,
    );
  }
  return Uint8Array.from(binStr, (c) => c.charCodeAt(0));
}
