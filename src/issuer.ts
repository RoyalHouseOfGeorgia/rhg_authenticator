/**
 * Pure issuer logic for the credential issuance interface.
 *
 * No DOM access, no side effects. Provides constants, form validation,
 * URL length estimation, and error formatting for the issuer UI.
 */

import { canonicalize } from './canonical.js';
import type { JsonObject } from './canonical.js';
import { base64urlEncode } from './base64url.js';
import { isValidDate } from './validation.js';

// ---------------------------------------------------------------------------
// QR / URL constants
// ---------------------------------------------------------------------------

export const VERIFY_BASE_URL = 'https://verify.royalhouseofgeorgia.ge/';
export const QR_VERSION = 24;
export const QR_MAX_URL_LENGTH = 625;
export const SIGNATURE_B64_LENGTH = 86;

export const URL_FIXED_OVERHEAD =
  VERIFY_BASE_URL.length + '?p='.length + '&s='.length + SIGNATURE_B64_LENGTH;
export const MAX_PAYLOAD_B64_CHARS = QR_MAX_URL_LENGTH - URL_FIXED_OVERHEAD;

export const QR_RENDER_WIDTH = 2048;
export const QR_PREVIEW_WIDTH = 512;
export const QR_MODULES = 113;
export const QR_QUIET_ZONE = 4;
export const QR_TOTAL_MODULES = QR_MODULES + QR_QUIET_ZONE * 2;
export const QR_PRINT_MIN_CM = 6.1;
export const QR_PRINT_REC_CM = 7.3;

// ---------------------------------------------------------------------------
// Honor titles
// ---------------------------------------------------------------------------

export const HONOR_TITLES = [
  'Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ',
  'Order of the St. Queen Tamar of Georgia',
  'Order of the Crown of Georgia',
  'Medal of Merit of the Royal House of Georgia',
  'Ennoblement',
] as const;

export type HonorTitle = (typeof HONOR_TITLES)[number];

// ---------------------------------------------------------------------------
// DOM element IDs (contract between HTML and JS)
// ---------------------------------------------------------------------------

export const DOM_IDS = {
  APP: 'app',
  AUTH_SECTION: 'auth-section',
  TOKEN_INPUT: 'token-input',
  TOKEN_SUBMIT: 'token-submit',
  FORM: 'issuer-form',
  RECIPIENT_INPUT: 'recipient',
  HONOR_SELECT: 'honor',
  DETAIL_INPUT: 'detail',
  DATE_INPUT: 'date',
  FORM_SUBMIT: 'form-submit',
  RESULT_SECTION: 'result-section',
  ERROR_BANNER: 'error-banner',
  QR_PREVIEW: 'qr-preview',
  QR_ACTIONS: 'qr-actions',
  STATUS_MESSAGE: 'status-message',
} as const;

// ---------------------------------------------------------------------------
// Form field types
// ---------------------------------------------------------------------------

export type FormFields = {
  recipient: string;
  honor: string;
  detail: string;
  date: string;
};

// ---------------------------------------------------------------------------
// computeUrlLength
// ---------------------------------------------------------------------------

export type UrlLengthResult = {
  estimatedLength: number;
  maxLength: number;
  fits: boolean;
};

/**
 * Estimate the full verification URL length for the given form fields and
 * authority string. Uses the same credential construction and canonicalization
 * pipeline as the server's `handleSign`.
 */
export function computeUrlLength(
  fields: FormFields,
  authority: string,
): UrlLengthResult {
  const credential: JsonObject = {
    version: 1,
    authority,
    recipient: fields.recipient,
    honor: fields.honor,
    detail: fields.detail,
    date: fields.date,
  };

  const payloadBytes = canonicalize(credential);
  const payloadB64 = base64urlEncode(payloadBytes);
  const estimatedLength = URL_FIXED_OVERHEAD + payloadB64.length;

  return {
    estimatedLength,
    maxLength: QR_MAX_URL_LENGTH,
    fits: estimatedLength <= QR_MAX_URL_LENGTH,
  };
}

// ---------------------------------------------------------------------------
// validateFormFields
// ---------------------------------------------------------------------------

/**
 * Validate issuer form fields. Returns `null` when valid, or a
 * human-readable error message string.
 */
export function validateFormFields(fields: FormFields): string | null {
  if (!fields.recipient) {
    return 'Recipient is required';
  }
  if (!fields.honor) {
    return 'Honor is required';
  }
  if (!(HONOR_TITLES as readonly string[]).includes(fields.honor)) {
    return 'Honor must be one of the recognized titles';
  }
  if (!fields.detail) {
    return 'Detail is required';
  }
  if (!fields.date) {
    return 'Date is required';
  }
  if (!isValidDate(fields.date)) {
    return 'Date must be a valid calendar date in YYYY-MM-DD format';
  }
  return null;
}

// ---------------------------------------------------------------------------
// formatSignError
// ---------------------------------------------------------------------------

type SignErrorBody = {
  error?: string;
  code?: string;
};

/**
 * Map an HTTP error status from the signing endpoint to a user-friendly
 * message. The `body` parameter is the parsed JSON response (if any).
 */
export function formatSignError(
  status: number,
  body: SignErrorBody | undefined,
): string {
  switch (status) {
    case 400:
      return (body?.error ?? '').slice(0, 200) || 'Invalid request — check your input and try again';
    case 401:
      return 'Authentication required — please re-enter your token';
    case 403:
      return 'Access denied — your token may have expired or been revoked';
    case 405:
      return 'Method not allowed';
    case 408:
      return 'Request timed out — please try again';
    case 413:
      return 'Payload too large — shorten the detail field';
    case 415:
      return 'Unsupported content type';
    case 429:
      return 'Too many requests — please wait a moment and try again';
    case 500:
      return 'Server error — please try again later';
    default:
      return `Unexpected error (HTTP ${status}) — please try again later`;
  }
}
