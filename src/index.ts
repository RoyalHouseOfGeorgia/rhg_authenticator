/**
 * @rhg/authenticator — Cryptographically verifiable credential library
 * for the Royal House of Georgia.
 */

// Canonical JSON serialization.
export { canonicalize } from './canonical.js';
export type { JsonValue, JsonObject } from './canonical.js';

// Base64URL and standard Base64 encoding/decoding.
export { base64urlEncode, base64urlDecode, base64Decode } from './base64url.js';

// Ed25519 cryptographic operations.
export { sign, verify, getPublicKey } from './crypto.js';

// Credential schema validation.
export { validateCredential, UnsupportedVersionError } from './credential.js';
export type { Credential, CredentialV1 } from './credential.js';

// Key registry schema, lookup, and decoding.
export {
  validateRegistry,
  findKeysByAuthority,
  isDateInRange,
  decodePublicKey,
} from './registry.js';
export type { KeyEntry, Registry } from './registry.js';

// Verification orchestrator.
export { verifyCredential, MAX_PAYLOAD_BYTES } from './verify.js';
export type {
  VerificationResult,
  VerificationSuccess,
  VerificationFailure,
} from './verify.js';
