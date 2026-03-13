import { createHash } from 'node:crypto';
import { canonicalize } from '../canonical.js';
import { base64urlEncode } from '../base64url.js';
import { sanitizeForError, validateCredential } from '../credential.js';
import { verify } from '../crypto.js';
import { MAX_PAYLOAD_BYTES } from '../verify.js';
import { validateSignatureLength } from './signature.js';
import { appendIssuanceRecord } from './log.js';
import type { SigningAdapter, IssuanceRecord } from './types.js';

export type SignRequest = {
  recipient: string;
  honor: string;
  detail: string;
  date: string;
};

export type SignResponse = {
  signature: string;
  payload: string;
  url: string;
  warning?: string;
};

export type SignError = {
  error: string;
  code: 'VALIDATION_FAILED' | 'SIGNING_FAILED';
};

/**
 * Handle a credential signing request end-to-end:
 * validate, canonicalize, sign, verify round-trip, log, and return.
 */
export async function handleSign(
  request: SignRequest,
  adapter: SigningAdapter,
  cachedPublicKey: Uint8Array,
  rawAuthority: string,
  logPath: string,
): Promise<SignResponse | SignError> {
  // 1. NFC-normalize string fields (date is ASCII-only, exempt).
  const recipient = request.recipient.normalize('NFC');
  const honor = request.honor.normalize('NFC');
  const detail = request.detail.normalize('NFC');
  const authority = rawAuthority.normalize('NFC');

  // 2. Construct full credential object.
  const credential = {
    version: 1 as const,
    authority,
    recipient,
    honor,
    detail,
    date: request.date,
  };

  // 3. Validate credential structure.
  try {
    validateCredential(credential);
  } catch (err) {
    console.error(
      'Credential validation failed:',
      sanitizeForError(err instanceof Error ? err.message : String(err)),
    );
    return {
      error: 'Invalid credential data',
      code: 'VALIDATION_FAILED',
    };
  }

  // 4. Canonicalize to payload bytes.
  const payloadBytes = canonicalize(credential);

  // 5. Enforce max payload size.
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    return {
      error: 'Payload exceeds maximum size',
      code: 'VALIDATION_FAILED',
    };
  }

  // 6. Sign via adapter.
  let rawSignature: Uint8Array;
  try {
    rawSignature = await adapter.signBytes(payloadBytes);
  } catch {
    return { error: 'Signing operation failed', code: 'SIGNING_FAILED' };
  }

  // 7. Normalize (validate length) signature.
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = validateSignatureLength(rawSignature);
  } catch {
    return { error: 'Signing operation failed', code: 'SIGNING_FAILED' };
  }

  // 8. Post-sign sanity check: verify round-trip.
  try {
    const valid = verify(signatureBytes, payloadBytes, cachedPublicKey);
    if (!valid) {
      console.error('Post-sign verification failed');
      return { error: 'Signing operation failed', code: 'SIGNING_FAILED' };
    }
  } catch (err) {
    if (err instanceof Error) {
      console.error('Post-sign verification threw:', sanitizeForError(err.message));
    }
    return { error: 'Signing operation failed', code: 'SIGNING_FAILED' };
  }

  // 9. Encode and build verification URL.
  const payloadB64 = base64urlEncode(payloadBytes);
  const sigB64 = base64urlEncode(signatureBytes);
  const url = `https://verify.royalhouseofgeorgia.ge/?p=${payloadB64}&s=${sigB64}`;

  // 10. Append issuance record to log.
  const payloadHash = createHash('sha256').update(payloadBytes).digest('hex');
  const record: IssuanceRecord = {
    timestamp: new Date().toISOString(),
    recipient,
    honor,
    detail,
    date: request.date,
    authority,
    payload_sha256: payloadHash,
    signature_b64url: sigB64,
  };

  let warning: string | undefined;
  try {
    await appendIssuanceRecord(logPath, record);
  } catch (err) {
    console.error('Log write failed:', sanitizeForError(err instanceof Error ? err.message : String(err)));
    warning = 'Credential signed but log write failed';
  }

  // 11. Return response.
  const response: SignResponse = {
    signature: sigB64,
    payload: payloadB64,
    url,
  };
  if (warning) {
    response.warning = warning;
  }
  return response;
}
