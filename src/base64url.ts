/**
 * Base64URL and standard Base64 encoding/decoding utilities.
 *
 * Uses `btoa`/`atob` (available since Node 16) with character replacement
 * for URL-safety. Handles padded and unpadded input.
 */

/** Encode a Uint8Array to a Base64URL string (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  const binStr = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  let b64: string;
  try {
    b64 = btoa(binStr);
  } catch (e) {
    throw new Error(
      `base64urlEncode: failed to encode bytes — ${(e as Error).message}`,
    );
  }
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a Base64URL string (padded or unpadded) to a Uint8Array. */
export function base64urlDecode(str: string): Uint8Array {
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

/** Decode a standard Base64 string (padded) to a Uint8Array. */
export function base64Decode(str: string): Uint8Array {
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
