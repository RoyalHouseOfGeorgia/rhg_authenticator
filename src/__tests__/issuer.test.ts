import { describe, expect, it } from 'vitest';
import { canonicalize } from '../canonical.js';
import type { JsonObject } from '../canonical.js';
import { base64urlEncode } from '../base64url.js';
import {
  VERIFY_BASE_URL,
  QR_MAX_URL_LENGTH,
  SIGNATURE_B64_LENGTH,
  URL_FIXED_OVERHEAD,
  MAX_PAYLOAD_B64_CHARS,
  QR_MODULES,
  QR_QUIET_ZONE,
  QR_TOTAL_MODULES,
  HONOR_TITLES,
  DOM_IDS,
  QR_VERSION,
  QR_RENDER_WIDTH,
  QR_PREVIEW_WIDTH,
  QR_PRINT_MIN_CM,
  QR_PRINT_REC_CM,
  computeUrlLength,
  validateFormFields,
  formatSignError,
} from '../issuer.js';
import type { FormFields } from '../issuer.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validFields(overrides?: Partial<FormFields>): FormFields {
  return {
    recipient: 'John Doe',
    honor: HONOR_TITLES[0],
    detail: 'For distinguished service',
    date: '2026-03-13',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Static assertions
// ---------------------------------------------------------------------------

describe('static constants', () => {
  it('URL_FIXED_OVERHEAD equals the sum of its components', () => {
    const expected =
      VERIFY_BASE_URL.length +
      '?p='.length +
      '&s='.length +
      SIGNATURE_B64_LENGTH;
    expect(URL_FIXED_OVERHEAD).toBe(expected);
  });

  it('VERIFY_BASE_URL is pure ASCII (byte length equals char length)', () => {
    const byteLength = new TextEncoder().encode(VERIFY_BASE_URL).length;
    expect(byteLength).toBe(VERIFY_BASE_URL.length);
  });

  it('all HONOR_TITLES entries are NFC-normalized', () => {
    for (const title of HONOR_TITLES) {
      expect(title).toBe(title.normalize('NFC'));
    }
  });

  it('QR_TOTAL_MODULES equals QR_MODULES + 2 * QR_QUIET_ZONE', () => {
    expect(QR_TOTAL_MODULES).toBe(QR_MODULES + QR_QUIET_ZONE * 2);
  });

  it('QR_MODULES equals 4 * QR_VERSION + 17', () => {
    expect(QR_MODULES).toBe(4 * QR_VERSION + 17);
  });

  it('MAX_PAYLOAD_B64_CHARS equals QR_MAX_URL_LENGTH - URL_FIXED_OVERHEAD', () => {
    expect(MAX_PAYLOAD_B64_CHARS).toBe(QR_MAX_URL_LENGTH - URL_FIXED_OVERHEAD);
  });

  it('exports expected QR rendering constants', () => {
    expect(QR_RENDER_WIDTH).toBe(2048);
    expect(QR_PREVIEW_WIDTH).toBe(512);
    expect(QR_PRINT_MIN_CM).toBe(6.1);
    expect(QR_PRINT_REC_CM).toBe(7.3);
  });

  it('DOM_IDS contains all expected keys', () => {
    const expectedKeys = [
      'APP',
      'AUTH_SECTION',
      'TOKEN_INPUT',
      'TOKEN_SUBMIT',
      'FORM',
      'RECIPIENT_INPUT',
      'HONOR_SELECT',
      'DETAIL_INPUT',
      'DATE_INPUT',
      'FORM_SUBMIT',
      'RESULT_SECTION',
      'ERROR_BANNER',
      'QR_PREVIEW',
      'QR_ACTIONS',
      'STATUS_MESSAGE',
    ];
    expect(Object.keys(DOM_IDS).sort()).toEqual(expectedKeys.sort());
  });
});

// ---------------------------------------------------------------------------
// computeUrlLength
// ---------------------------------------------------------------------------

describe('computeUrlLength', () => {
  const authority = 'Royal House of Georgia';

  it('returns fits: true for short fields', () => {
    const result = computeUrlLength(validFields(), authority);
    expect(result.fits).toBe(true);
    expect(result.maxLength).toBe(QR_MAX_URL_LENGTH);
    expect(result.estimatedLength).toBeLessThanOrEqual(QR_MAX_URL_LENGTH);
  });

  it('returns fits: false for very long fields', () => {
    const longDetail = 'A'.repeat(1000);
    const result = computeUrlLength(
      validFields({ detail: longDetail }),
      authority,
    );
    expect(result.fits).toBe(false);
    expect(result.estimatedLength).toBeGreaterThan(QR_MAX_URL_LENGTH);
  });

  it('maxLength is always QR_MAX_URL_LENGTH', () => {
    const result = computeUrlLength(validFields(), authority);
    expect(result.maxLength).toBe(QR_MAX_URL_LENGTH);
  });

  it('handles Georgian characters (multi-byte UTF-8)', () => {
    const georgianFields = validFields({
      recipient: '\u10D2\u10D4\u10DD\u10E0\u10D2\u10D8',
      detail: '\u10E1\u10D0\u10E5\u10D0\u10E0\u10D7\u10D5\u10D4\u10DA\u10DD',
    });
    const result = computeUrlLength(georgianFields, authority);
    // Georgian chars are 3 bytes each in UTF-8, so base64 will be longer
    // than JS string .length might suggest
    expect(result.estimatedLength).toBeGreaterThan(URL_FIXED_OVERHEAD);
    expect(typeof result.fits).toBe('boolean');
  });

  it('exact boundary: fits at QR_MAX_URL_LENGTH', () => {
    // Build a credential and find a detail length that hits exactly 625
    // We do this iteratively — try a detail, measure, adjust
    let lo = 1;
    let hi = 600;
    let detail = '';
    while (lo <= hi) {
      const mid = Math.floor((lo + hi) / 2);
      detail = 'X'.repeat(mid);
      const r = computeUrlLength(validFields({ detail }), authority);
      if (r.estimatedLength <= QR_MAX_URL_LENGTH) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    // hi is the largest detail length that fits
    const fittingDetail = 'X'.repeat(hi);
    const fittingResult = computeUrlLength(
      validFields({ detail: fittingDetail }),
      authority,
    );
    expect(fittingResult.fits).toBe(true);
    expect(fittingResult.estimatedLength).toBeLessThanOrEqual(
      QR_MAX_URL_LENGTH,
    );

    // One more char should not fit
    const overDetail = 'X'.repeat(hi + 1);
    const overResult = computeUrlLength(
      validFields({ detail: overDetail }),
      authority,
    );
    expect(overResult.fits).toBe(false);
    expect(overResult.estimatedLength).toBeGreaterThan(QR_MAX_URL_LENGTH);
  });

  it('cross-check: matches the handleSign credential construction pipeline', () => {
    const fields = validFields();
    const result = computeUrlLength(fields, authority);

    // Replicate what handleSign does
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
    // Simulate a 64-byte signature → 86 base64url chars
    const fakeSig = new Uint8Array(64);
    const sigB64 = base64urlEncode(fakeSig);
    expect(sigB64.length).toBe(SIGNATURE_B64_LENGTH);

    const actualUrl = `https://verify.royalhouseofgeorgia.ge/?p=${payloadB64}&s=${sigB64}`;
    expect(result.estimatedLength).toBe(actualUrl.length);
  });
});

// ---------------------------------------------------------------------------
// validateFormFields
// ---------------------------------------------------------------------------

describe('validateFormFields', () => {
  it('returns null for valid input', () => {
    expect(validateFormFields(validFields())).toBeNull();
  });

  it('returns error when recipient is empty', () => {
    const result = validateFormFields(validFields({ recipient: '' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Recipient');
  });

  it('returns error when honor is empty', () => {
    const result = validateFormFields(validFields({ honor: '' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Honor');
  });

  it('returns error when honor is not in HONOR_TITLES', () => {
    const result = validateFormFields(
      validFields({ honor: 'Made Up Award' }),
    );
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Honor');
  });

  it('returns null when honor is a valid HONOR_TITLES entry', () => {
    for (const title of HONOR_TITLES) {
      expect(validateFormFields(validFields({ honor: title }))).toBeNull();
    }
  });

  it('returns error when detail is empty', () => {
    const result = validateFormFields(validFields({ detail: '' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Detail');
  });

  it('returns error when date is empty', () => {
    const result = validateFormFields(validFields({ date: '' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Date');
  });

  it('returns error for invalid date format', () => {
    const result = validateFormFields(validFields({ date: '13-03-2026' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Date');
  });

  it('returns null for Feb 29 in a leap year', () => {
    expect(
      validateFormFields(validFields({ date: '2024-02-29' })),
    ).toBeNull();
  });

  it('returns error for Feb 29 in a non-leap year', () => {
    const result = validateFormFields(validFields({ date: '2023-02-29' }));
    expect(result).toBeTypeOf('string');
    expect(result).toContain('Date');
  });

  it('returns error for Feb 30', () => {
    const result = validateFormFields(validFields({ date: '2024-02-30' }));
    expect(result).toBeTypeOf('string');
  });

  it('returns error for non-numeric date segments', () => {
    const result = validateFormFields(validFields({ date: 'abcd-ef-gh' }));
    expect(result).toBeTypeOf('string');
  });

  it('returns error for year < 1 (year 0000)', () => {
    const result = validateFormFields(validFields({ date: '0000-01-15' }));
    expect(result).toBeTypeOf('string');
  });
});

// ---------------------------------------------------------------------------
// formatSignError
// ---------------------------------------------------------------------------

describe('formatSignError', () => {
  it('returns body.error for 400 when present', () => {
    const msg = formatSignError(400, { error: 'Bad recipient field' });
    expect(msg).toBe('Bad recipient field');
  });

  it('returns fallback for 400 when body has no error', () => {
    const msg = formatSignError(400, {});
    expect(msg).toContain('Invalid request');
  });

  it('returns auth message for 401', () => {
    const msg = formatSignError(401, undefined);
    expect(msg).toContain('Authentication');
  });

  it('returns access denied for 403', () => {
    const msg = formatSignError(403, { error: 'Forbidden' });
    expect(msg).toContain('Access denied');
  });

  it('returns method not allowed for 405', () => {
    const msg = formatSignError(405, undefined);
    expect(msg).toContain('Method not allowed');
  });

  it('returns timeout message for 408', () => {
    const msg = formatSignError(408, undefined);
    expect(msg).toContain('timed out');
  });

  it('returns payload too large for 413', () => {
    const msg = formatSignError(413, undefined);
    expect(msg).toContain('Payload too large');
  });

  it('returns unsupported content type for 415', () => {
    const msg = formatSignError(415, undefined);
    expect(msg).toContain('Unsupported content type');
  });

  it('returns rate limit message for 429', () => {
    const msg = formatSignError(429, undefined);
    expect(msg).toContain('Too many requests');
  });

  it('returns server error for 500', () => {
    const msg = formatSignError(500, undefined);
    expect(msg).toContain('Server error');
  });

  it('returns generic fallback for unknown status', () => {
    const msg = formatSignError(502, undefined);
    expect(msg).toContain('Unexpected error');
    expect(msg).toContain('502');
  });

  it('handles undefined body gracefully', () => {
    const msg = formatSignError(400, undefined);
    expect(msg).toContain('Invalid request');
  });

  it('handles body with no error field', () => {
    const msg = formatSignError(400, { code: 'SOMETHING' });
    expect(msg).toContain('Invalid request');
  });

  it('handles body with unexpected fields', () => {
    const msg = formatSignError(500, { code: 'INTERNAL' } as never);
    expect(msg).toContain('Server error');
  });

  it('truncates long body.error to 200 characters for 400', () => {
    const longError = 'X'.repeat(300);
    const msg = formatSignError(400, { error: longError });
    expect(msg).toHaveLength(200);
    expect(msg).toBe('X'.repeat(200));
  });

  it('uses fallback when body.error is empty string for 400', () => {
    const msg = formatSignError(400, { error: '' });
    expect(msg).toContain('Invalid request');
  });
});
