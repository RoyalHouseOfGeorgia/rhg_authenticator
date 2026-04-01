// @vitest-environment happy-dom

import { createHash } from 'crypto';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  parseParams,
  getRegistryUrl,
  getRevocationListUrl,
  fetchRegistry,
  fetchRevocationList,
  runVerification,
  renderResult,
  initVerifyPage,
} from '../verify-page.js';
import { sign } from '../crypto.js';
import { canonicalize } from '../canonical.js';
import { base64urlEncode } from '../base64url.js';

import type { PageParams, VerifyPageResult } from '../verify-page.js';
import type { Registry } from '../registry.js';
import type { RevocationList } from '../revocation.js';
import {
  makeKeypair,
  makeKeyEntry,
  makeRegistry,
  validCredentialObj,
} from './helpers.js';

/** Create a signed credential as base64url-encoded PageParams. */
function makeSignedParams(
  secretKey: Uint8Array,
  credObj?: Record<string, unknown>,
): PageParams {
  const cred = credObj ?? validCredentialObj();
  const payloadBytes = canonicalize(cred as Record<string, string | number>);
  const signatureBytes = sign(payloadBytes, secretKey);
  return {
    payload: base64urlEncode(payloadBytes),
    signature: base64urlEncode(signatureBytes),
  };
}

/** Create a valid registry JSON response body. */
function makeRegistryJson(registry: Registry): string {
  return JSON.stringify(registry);
}

/** Create a valid revocation list JSON response body. */
function makeRevocationListJson(list: RevocationList): string {
  return JSON.stringify(list);
}

/** Compute SHA-256 hex of a credential object's canonical bytes. */
function computePayloadHash(credObj?: Record<string, unknown>): string {
  const cred = credObj ?? validCredentialObj();
  const payloadBytes = canonicalize(cred as Record<string, string | number>);
  return createHash('sha256').update(payloadBytes).digest('hex');
}

/** Build a revocation list with a single entry for the given hash. */
function makeRevocationList(hash: string, revokedOn = '2026-03-25'): RevocationList {
  return { revocations: [{ hash, revoked_on: revokedOn }] };
}

/** Build an empty revocation list. */
function makeEmptyRevocationList(): RevocationList {
  return { revocations: [] };
}

// ---------------------------------------------------------------------------
// parseParams
// ---------------------------------------------------------------------------

describe('parseParams', () => {
  it('extracts p and s from valid query string', () => {
    const result = parseParams('?p=abc123&s=def456');
    expect(result).toEqual({ payload: 'abc123', signature: 'def456' });
  });

  it('returns error for missing p', () => {
    const result = parseParams('?s=def456');
    expect(result).toEqual({ error: 'Missing credential data (p parameter)' });
  });

  it('returns error for missing s', () => {
    const result = parseParams('?p=abc123');
    expect(result).toEqual({ error: 'Missing signature (s parameter)' });
  });

  it('returns error for empty p (present but empty value)', () => {
    const result = parseParams('?p=&s=def456');
    expect(result).toEqual({ error: 'Empty credential data (p parameter)' });
  });

  it('returns error for empty s', () => {
    const result = parseParams('?p=abc123&s=');
    expect(result).toEqual({ error: 'Empty signature (s parameter)' });
  });

  it('returns error when both missing (reports p first)', () => {
    const result = parseParams('');
    expect(result).toEqual({ error: 'Missing credential data (p parameter)' });
  });

  it('handles URL-encoded characters in params', () => {
    // %2B is '+', URLSearchParams decodes it
    const result = parseParams('?p=abc%2B123&s=def%2F456');
    expect(result).toEqual({ payload: 'abc+123', signature: 'def/456' });
  });

  it('handles duplicate params — returns first occurrence', () => {
    const result = parseParams('?p=first&p=second&s=sig');
    expect(result).toEqual({ payload: 'first', signature: 'sig' });
  });
});

// ---------------------------------------------------------------------------
// getRegistryUrl
// ---------------------------------------------------------------------------

describe('getRegistryUrl', () => {
  const originalLocation = window.location;

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  it('returns absolute URL for production hostname', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: 'verify.royalhouseofgeorgia.ge' },
      writable: true,
      configurable: true,
    });
    expect(getRegistryUrl()).toBe(
      'https://verify.royalhouseofgeorgia.ge/keys/registry.json',
    );
  });

  it('returns relative URL for localhost', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: 'localhost' },
      writable: true,
      configurable: true,
    });
    expect(getRegistryUrl()).toBe('/keys/registry.json');
  });

  it('returns relative URL for LAN IP', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: '192.168.1.100' },
      writable: true,
      configurable: true,
    });
    expect(getRegistryUrl()).toBe('/keys/registry.json');
  });
});

// ---------------------------------------------------------------------------
// getRevocationListUrl
// ---------------------------------------------------------------------------

describe('getRevocationListUrl', () => {
  const originalLocation = window.location;

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  it('returns absolute URL for production hostname', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: 'verify.royalhouseofgeorgia.ge' },
      writable: true,
      configurable: true,
    });
    expect(getRevocationListUrl()).toBe(
      'https://verify.royalhouseofgeorgia.ge/keys/revocations.json',
    );
  });

  it('returns relative URL for localhost', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: 'localhost' },
      writable: true,
      configurable: true,
    });
    expect(getRevocationListUrl()).toBe('/keys/revocations.json');
  });

  it('returns relative URL for LAN IP', () => {
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, hostname: '192.168.1.100' },
      writable: true,
      configurable: true,
    });
    expect(getRevocationListUrl()).toBe('/keys/revocations.json');
  });
});

// ---------------------------------------------------------------------------
// fetchRegistry
// ---------------------------------------------------------------------------

describe('fetchRegistry', () => {
  const { publicKey } = makeKeypair();
  const validRegistry = makeRegistry(makeKeyEntry(publicKey));
  const validJson = makeRegistryJson(validRegistry);

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns validated registry on success', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(validJson, { status: 200 }),
    );
    const result = await fetchRegistry('/keys/registry.json');
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].authority).toBe('Test Authority');
  });

  it('throws on network error', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Network failure'));
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Failed to contact verification service',
    );
  });

  it('throws on non-200 HTTP status', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('Not found', { status: 404 }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Verification service returned an error',
    );
  });

  it('throws on invalid JSON response', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('not json {{', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Registry data is corrupted',
    );
  });

  it('throws when response body exceeds 1 MiB', async () => {
    const oversized = 'x'.repeat(1024 * 1024 + 1);
    vi.mocked(fetch).mockResolvedValue(
      new Response(oversized, { status: 200 }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Registry response exceeds size limit',
    );
  });

  it('accepts response body under 1 MiB with valid registry JSON', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(validJson, { status: 200 }),
    );
    const result = await fetchRegistry('/keys/registry.json');
    // validJson is well under 1 MiB — just verify it parses successfully
    expect(result.keys).toHaveLength(1);
  });

  it('throws on schema validation failure (valid JSON, invalid registry)', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ keys: [] }), { status: 200 }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Registry data is invalid',
    );
  });

  it('passes credentials omit and no-referrer to fetch', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(validJson, { status: 200 }),
    );
    await fetchRegistry('/keys/registry.json');
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      '/keys/registry.json',
      expect.objectContaining({
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      }),
    );
  });

  it('rejects early when Content-Length header exceeds size limit', async () => {
    const headers = new Headers({ 'Content-Length': '2000000' });
    vi.mocked(fetch).mockResolvedValue(
      new Response('{}', { status: 200, headers }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Registry response exceeds size limit',
    );
  });

  it('rejects non-numeric Content-Length header', async () => {
    const headers = new Headers({ 'Content-Length': 'bogus' });
    vi.mocked(fetch).mockResolvedValue(
      new Response('{}', { status: 200, headers }),
    );
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      'Registry response exceeds size limit',
    );
  });

  it('throws on timeout', async () => {
    vi.useFakeTimers();
    vi.mocked(fetch).mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          (init?.signal as AbortSignal)?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        }),
    );

    const promise = fetchRegistry('/keys/registry.json');
    vi.advanceTimersByTime(10_000);
    await expect(promise).rejects.toThrow(
      'Failed to contact verification service',
    );
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// fetchRevocationList
// ---------------------------------------------------------------------------

describe('fetchRevocationList', () => {
  const validRevocationList = makeEmptyRevocationList();
  const validJson = makeRevocationListJson(validRevocationList);

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns validated revocation list on success', async () => {
    const list = makeRevocationList('a'.repeat(64));
    vi.mocked(fetch).mockResolvedValue(
      new Response(makeRevocationListJson(list), { status: 200 }),
    );
    const result = await fetchRevocationList('/keys/revocations.json');
    expect(result.revocations).toHaveLength(1);
    expect(result.revocations[0].hash).toBe('a'.repeat(64));
  });

  it('throws on network error', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Network failure'));
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Failed to contact revocation service',
    );
  });

  it('throws on non-200 HTTP status', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('Not found', { status: 404 }),
    );
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Revocation service returned an error',
    );
  });

  it('throws on invalid JSON response', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('not json {{', { status: 200 }),
    );
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Revocation data is corrupted',
    );
  });

  it('throws when response body exceeds 1 MiB', async () => {
    const oversized = 'x'.repeat(1024 * 1024 + 1);
    vi.mocked(fetch).mockResolvedValue(
      new Response(oversized, { status: 200 }),
    );
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Revocation response exceeds size limit',
    );
  });

  it('throws on schema validation failure (valid JSON, invalid schema)', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ wrong_field: [] }), { status: 200 }),
    );
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Revocation data is invalid',
    );
  });

  it('throws on timeout', async () => {
    vi.useFakeTimers();
    vi.mocked(fetch).mockImplementation(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          (init?.signal as AbortSignal)?.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
        }),
    );

    const promise = fetchRevocationList('/keys/revocations.json');
    vi.advanceTimersByTime(10_000);
    await expect(promise).rejects.toThrow(
      'Failed to contact revocation service',
    );
    vi.useRealTimers();
  });

  it('passes credentials omit and no-referrer to fetch', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(validJson, { status: 200 }),
    );
    await fetchRevocationList('/keys/revocations.json');
    expect(vi.mocked(fetch)).toHaveBeenCalledWith(
      '/keys/revocations.json',
      expect.objectContaining({
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      }),
    );
  });

  it('rejects early when Content-Length header exceeds size limit', async () => {
    const headers = new Headers({ 'Content-Length': '2000000' });
    vi.mocked(fetch).mockResolvedValue(
      new Response('{}', { status: 200, headers }),
    );
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      'Revocation response exceeds size limit',
    );
  });
});

// ---------------------------------------------------------------------------
// fetchAndValidate error label consistency
// ---------------------------------------------------------------------------

describe('fetchAndValidate error labels', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetchRegistry network error message contains "verification"', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Network failure'));
    await expect(fetchRegistry('/keys/registry.json')).rejects.toThrow(
      /verification/,
    );
  });

  it('fetchRevocationList network error message contains "revocation"', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Network failure'));
    await expect(fetchRevocationList('/keys/revocations.json')).rejects.toThrow(
      /revocation/,
    );
  });
});

// ---------------------------------------------------------------------------
// runVerification
// ---------------------------------------------------------------------------

describe('runVerification', () => {
  const { secretKey, publicKey } = makeKeypair();
  const entry = makeKeyEntry(publicKey);
  const registry = makeRegistry(entry);

  it('returns valid result with fields from payload and authority from registry key', async () => {
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, registry);
    expect(result).toMatchObject({
      status: 'valid',
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
      authority: 'Test Authority',
    });
  });

  it('returns invalid for tampered payload', async () => {
    const params = makeSignedParams(secretKey);
    // Tamper the payload (change a character)
    const tamperedPayload = base64urlEncode(
      canonicalize(validCredentialObj({ recipient: 'Evil Eve' }) as Record<string, string | number>),
    );
    const result = await runVerification(
      { payload: tamperedPayload, signature: params.signature },
      registry,
    );
    expect(result.status).toBe('invalid');
  });

  it('returns error for invalid Base64URL in p', async () => {
    const result = await runVerification(
      { payload: '!!!invalid!!!', signature: 'AAAA' },
      registry,
    );
    expect(result).toEqual({ status: 'error', message: 'Invalid credential encoding' });
  });

  it('returns error for invalid Base64URL in s', async () => {
    const params = makeSignedParams(secretKey);
    const result = await runVerification(
      { payload: params.payload, signature: '!!!invalid!!!' },
      registry,
    );
    expect(result).toEqual({ status: 'error', message: 'Invalid signature encoding' });
  });

  it('returns invalid for signature not exactly 64 bytes', async () => {
    const params = makeSignedParams(secretKey);
    // Create a valid base64url string that decodes to 32 bytes instead of 64
    const shortSig = base64urlEncode(new Uint8Array(32));
    const result = await runVerification(
      { payload: params.payload, signature: shortSig },
      registry,
    );
    // Signature length validated by verifyCredential, returns invalid (not error).
    expect(result).toEqual({ status: 'invalid', reason: 'invalid signature length' });
  });

  it('returns invalid with date-mismatch reason', async () => {
    const restrictedEntry = makeKeyEntry(publicKey, { from: '2025-01-01', to: '2025-12-31' });
    const restrictedRegistry = makeRegistry(restrictedEntry);
    // Credential date is 2024-06-15, key valid from 2025
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, restrictedRegistry);
    expect(result.status).toBe('invalid');
    expect((result as { status: 'invalid'; reason: string }).reason).toContain(
      'date outside key validity period',
    );
  });

  it('rejects payload with non-string field value', async () => {
    const badObj = { ...validCredentialObj(), recipient: 123 };
    const payloadBytes = canonicalize(badObj as Record<string, string | number>);
    const signatureBytes = sign(payloadBytes, secretKey);
    const params: PageParams = {
      payload: base64urlEncode(payloadBytes),
      signature: base64urlEncode(signatureBytes),
    };
    const result = await runVerification(params, registry);
    expect(result.status).toBe('invalid');
  });

  it('returns invalid for completely garbled payload', async () => {
    const badPayload = base64urlEncode(new TextEncoder().encode('not json {{'));
    const sig = base64urlEncode(new Uint8Array(64));
    const result = await runVerification(
      { payload: badPayload, signature: sig },
      registry,
    );
    expect(result.status).toBe('invalid');
  });

  it('valid result authority comes from registry key, not credential payload', async () => {
    const customEntry = makeKeyEntry(publicKey, { authority: 'Registry Authority Name' });
    const customRegistry = makeRegistry(customEntry);
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, customRegistry);
    expect(result.status).toBe('valid');
    expect((result as { status: 'valid'; authority: string }).authority).toBe(
      'Registry Authority Name',
    );
  });

  // --- Revocation tests ---

  it('returns revoked for a credential in the revocation list', async () => {
    const hash = computePayloadHash();
    const revocationList = makeRevocationList(hash);
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, registry, revocationList);
    expect(result).toEqual({ status: 'revoked' });
  });

  it('returns valid for credential with empty revocation list', async () => {
    const revocationList = makeEmptyRevocationList();
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, registry, revocationList);
    expect(result.status).toBe('valid');
    // revocationUnknown should NOT be set when revocation was successfully checked
    expect((result as { revocationUnknown?: boolean }).revocationUnknown).toBeUndefined();
  });

  it('returns valid with revocationUnknown when revocation fetch failed', async () => {
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, registry, undefined, true);
    expect(result.status).toBe('valid');
    expect((result as { revocationUnknown?: boolean }).revocationUnknown).toBe(true);
  });

  it('returns valid with revocationUnknown when no revocation list provided', async () => {
    const params = makeSignedParams(secretKey);
    const result = await runVerification(params, registry);
    expect(result.status).toBe('valid');
    expect((result as { revocationUnknown?: boolean }).revocationUnknown).toBe(true);
  });

  it('skips revocation check when crypto.subtle is unavailable', async () => {
    const hash = computePayloadHash();
    const revocationList = makeRevocationList(hash);
    const params = makeSignedParams(secretKey);

    // Temporarily remove crypto.subtle
    const originalCrypto = globalThis.crypto;
    const cryptoWithoutSubtle = { ...originalCrypto } as Crypto;
    Object.defineProperty(cryptoWithoutSubtle, 'subtle', { value: undefined, configurable: true });
    vi.stubGlobal('crypto', cryptoWithoutSubtle);

    try {
      const result = await runVerification(params, registry, revocationList);
      // Should be valid (revocation check skipped) with revocationUnknown
      expect(result.status).toBe('valid');
      expect((result as { revocationUnknown?: boolean }).revocationUnknown).toBe(true);
    } finally {
      vi.stubGlobal('crypto', originalCrypto);
    }
  });

  it('returns revoked via crypto.subtle.digest → hex → revocation set lookup end-to-end', async () => {
    // Build a signed credential using a fresh keypair so it is independent of
    // other tests.
    const { secretKey: sk, publicKey: pk } = makeKeypair(42);
    const credObj = validCredentialObj({ recipient: 'Crypto Subtle Test' });
    const payloadBytes = canonicalize(credObj as Record<string, string | number>);
    const signatureBytes = sign(payloadBytes, sk);
    const params: PageParams = {
      payload: base64urlEncode(payloadBytes),
      signature: base64urlEncode(signatureBytes),
    };

    // Compute the hash the same way runVerification does: via crypto.subtle.digest
    // then hex-encode with zero-padded bytes.
    const hashBuffer = await crypto.subtle.digest('SHA-256', payloadBytes as Uint8Array<ArrayBuffer>);
    const payloadHash = [...new Uint8Array(hashBuffer)]
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Build a registry that will accept the credential, and a revocation list
    // that marks the computed hash as revoked.
    const testRegistry = makeRegistry(makeKeyEntry(pk));
    const revocationList = makeRevocationList(payloadHash);

    const result = await runVerification(params, testRegistry, revocationList);
    expect(result.status).toBe('revoked');
  });
});

// ---------------------------------------------------------------------------
// renderResult
// ---------------------------------------------------------------------------

describe('renderResult', () => {
  let container: HTMLDivElement;

  beforeEach(() => {
    container = document.createElement('div');
    container.id = 'result';
    document.body.appendChild(container);
  });

  afterEach(() => {
    container.remove();
  });

  it('renders valid result with recipient, honor, date, authority and success styling', () => {
    const result: VerifyPageResult = {
      status: 'valid',
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
      authority: 'Test Authority',
    };
    renderResult(result, container);

    const wrapper = container.querySelector('.result-valid');
    expect(wrapper).not.toBeNull();
    expect(wrapper!.querySelector('.status-banner')!.textContent).toBe('Verified');
    expect(container.textContent).toContain('Jane Doe');
    expect(container.textContent).toContain('Test Honor');
    expect(container.textContent).toContain('Test Detail');
    expect(container.textContent).toContain('2024-06-15');
    expect(container.textContent).toContain('Test Authority');
    // Verify field structure
    const fields = container.querySelectorAll('.credential-field');
    expect(fields).toHaveLength(5);
  });

  it('renders invalid result with rejection reason, no credential fields in DOM', () => {
    const result: VerifyPageResult = {
      status: 'invalid',
      reason: 'xunit-sentinel-reason',
    };
    renderResult(result, container);

    const wrapper = container.querySelector('.result-invalid');
    expect(wrapper).not.toBeNull();
    expect(wrapper!.querySelector('.status-banner')!.textContent).toBe('Not Verified');
    expect(container.textContent).toContain('This credential could not be verified');
    expect(container.textContent).not.toContain('xunit-sentinel-reason');
    expect(container.querySelector('a[href="mailto:secretary@royalhouseofgeorgia.ge"]')).not.toBeNull();
    // No credential fields should appear
    expect(container.querySelectorAll('.credential-field')).toHaveLength(0);
  });

  it('renders error result with warning label and message', () => {
    const result: VerifyPageResult = {
      status: 'error',
      message: 'xunit-sentinel-message',
    };
    renderResult(result, container);

    const wrapper = container.querySelector('.result-error');
    expect(wrapper).not.toBeNull();
    expect(wrapper!.querySelector('.status-banner')!.textContent).toBe('Verification Error');
    expect(container.textContent).toContain('We were unable to complete the verification');
    expect(container.textContent).not.toContain('xunit-sentinel-message');
    expect(container.querySelector('a[href="mailto:secretary@royalhouseofgeorgia.ge"]')).not.toBeNull();
  });

  it('does not render credential fields on invalid result (security)', () => {
    const result: VerifyPageResult = {
      status: 'invalid',
      reason: 'tampered',
    };
    renderResult(result, container);

    // Verify no credential field elements exist
    expect(container.querySelectorAll('.credential-field')).toHaveLength(0);
    expect(container.querySelectorAll('.field-value')).toHaveLength(0);
  });

  it('all text uses textContent — script tag in field appears as literal text', () => {
    const xssAttempt = '<script>alert("xss")</script>';
    const result: VerifyPageResult = {
      status: 'valid',
      recipient: xssAttempt,
      honor: 'test',
      detail: 'test',
      date: '2024-01-01',
      authority: 'test',
    };
    renderResult(result, container);

    // The script tag should appear as literal text, not as an element
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain(xssAttempt);
  });

  it('renders info page with heading, description and homepage link', () => {
    const result: VerifyPageResult = { status: 'info' };
    renderResult(result, container);

    const wrapper = container.querySelector('.result-info');
    expect(wrapper).not.toBeNull();
    expect(container.textContent).toContain('Digital Credential Verification');
    expect(container.textContent).toContain('verifies honors and credentials');
    const link = container.querySelector('a[href="https://royalhouseofgeorgia.ge"]');
    expect(link).not.toBeNull();
    expect(link!.textContent).toBe('Visit the Royal House of Georgia');
  });

  it('mailto link present in both invalid and error states', () => {
    renderResult({ status: 'invalid', reason: 'x' }, container);
    expect(container.querySelector('a[href="mailto:secretary@royalhouseofgeorgia.ge"]')).not.toBeNull();

    renderResult({ status: 'error', message: 'x' }, container);
    expect(container.querySelector('a[href="mailto:secretary@royalhouseofgeorgia.ge"]')).not.toBeNull();
  });

  // --- Revocation render tests ---

  it('renders revoked result with banner, detail text, contact link, and no credential fields', () => {
    const result: VerifyPageResult = { status: 'revoked' };
    renderResult(result, container);

    const wrapper = container.querySelector('.result-revoked');
    expect(wrapper).not.toBeNull();
    expect(wrapper!.querySelector('.status-banner')!.textContent).toBe('Credential Revoked');
    expect(container.textContent).toContain('This credential has been revoked by the issuing authority');
    expect(container.querySelector('a[href="mailto:secretary@royalhouseofgeorgia.ge"]')).not.toBeNull();
    // No credential fields should appear
    expect(container.querySelectorAll('.credential-field')).toHaveLength(0);
  });

  it('renders valid result with revocationUnknown note', () => {
    const result: VerifyPageResult = {
      status: 'valid',
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
      authority: 'Test Authority',
      revocationUnknown: true,
    };
    renderResult(result, container);

    const note = container.querySelector('.revocation-unknown');
    expect(note).not.toBeNull();
    expect(note!.textContent).toBe('Revocation status could not be verified.');
    // Credential fields should still be present
    expect(container.querySelectorAll('.credential-field')).toHaveLength(5);
  });

  it('does not render revocationUnknown note when flag is absent', () => {
    const result: VerifyPageResult = {
      status: 'valid',
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
      authority: 'Test Authority',
    };
    renderResult(result, container);

    expect(container.querySelector('.revocation-unknown')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// initVerifyPage end-to-end
// ---------------------------------------------------------------------------

describe('initVerifyPage', () => {
  const { secretKey, publicKey } = makeKeypair(50);
  const entry = makeKeyEntry(publicKey);
  const registry = makeRegistry(entry);

  let container: HTMLDivElement;

  beforeEach(() => {
    container = document.createElement('div');
    container.id = 'result';
    document.body.appendChild(container);
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    document.querySelectorAll('.dev-warning').forEach((el) => el.remove());
    container.remove();
    vi.unstubAllGlobals();
  });

  /** Mock fetch to respond differently based on URL. */
  function mockFetchForBoth(registryJson: string, revocationJson: string) {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes('registry.json')) {
        return Promise.resolve(new Response(registryJson, { status: 200 }));
      }
      if (url.includes('revocations.json')) {
        return Promise.resolve(new Response(revocationJson, { status: 200 }));
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });
  }

  it('full happy path: valid result rendered with revocation list', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'verify.royalhouseofgeorgia.ge',
      },
      writable: true,
      configurable: true,
    });

    mockFetchForBoth(
      makeRegistryJson(registry),
      makeRevocationListJson(makeEmptyRevocationList()),
    );

    await initVerifyPage();

    expect(container.querySelector('.result-valid')).not.toBeNull();
    expect(container.textContent).toContain('Jane Doe');
    expect(container.textContent).toContain('Verified');
    // No revocation unknown note since revocation list was fetched
    expect(container.querySelector('.revocation-unknown')).toBeNull();
  });

  it('missing params renders info page without fetching', async () => {
    Object.defineProperty(window, 'location', {
      value: { ...window.location, search: '', hostname: 'localhost' },
      writable: true,
      configurable: true,
    });

    await initVerifyPage();

    expect(container.querySelector('.result-info')).not.toBeNull();
    expect(container.textContent).toContain('Digital Credential Verification');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('registry fetch failure renders error', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    vi.mocked(fetch).mockRejectedValue(new TypeError('Network error'));

    await initVerifyPage();

    expect(container.querySelector('.result-error')).not.toBeNull();
    expect(container.textContent).toContain('We were unable to complete the verification');
  });

  it('invalid credential renders invalid result', async () => {
    // Sign with one key, but registry has a different key
    const otherPair = makeKeypair(99);
    const params = makeSignedParams(secretKey);
    const otherRegistry = makeRegistry(makeKeyEntry(otherPair.publicKey));

    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    mockFetchForBoth(
      makeRegistryJson(otherRegistry),
      makeRevocationListJson(makeEmptyRevocationList()),
    );

    await initVerifyPage();

    expect(container.querySelector('.result-invalid')).not.toBeNull();
    expect(container.textContent).toContain('Not Verified');
  });

  it('shows dev-warning on localhost', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    mockFetchForBoth(
      makeRegistryJson(registry),
      makeRevocationListJson(makeEmptyRevocationList()),
    );

    await initVerifyPage();

    expect(document.querySelector('.dev-warning')).not.toBeNull();
    expect(document.querySelector('.dev-warning')!.textContent).toBe(
      'Development mode — not the official verification page',
    );
  });

  it('does not show dev-warning on production hostname', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'verify.royalhouseofgeorgia.ge',
      },
      writable: true,
      configurable: true,
    });

    mockFetchForBoth(
      makeRegistryJson(registry),
      makeRevocationListJson(makeEmptyRevocationList()),
    );

    await initVerifyPage();

    expect(document.querySelector('.dev-warning')).toBeNull();
  });

  // --- Revocation integration tests ---

  it('revocation list fetch failure shows valid result with revocation unknown note', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes('registry.json')) {
        return Promise.resolve(new Response(makeRegistryJson(registry), { status: 200 }));
      }
      // Revocation fetch fails
      return Promise.reject(new TypeError('Revocation network error'));
    });

    await initVerifyPage();

    expect(container.querySelector('.result-valid')).not.toBeNull();
    expect(container.textContent).toContain('Jane Doe');
    expect(container.querySelector('.revocation-unknown')).not.toBeNull();
    expect(container.querySelector('.revocation-unknown')!.textContent).toBe(
      'Revocation status could not be verified.',
    );
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it('revoked credential renders revoked state', async () => {
    const hash = computePayloadHash();
    const revocationList = makeRevocationList(hash);
    const params = makeSignedParams(secretKey);

    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    mockFetchForBoth(
      makeRegistryJson(registry),
      makeRevocationListJson(revocationList),
    );

    await initVerifyPage();

    expect(container.querySelector('.result-revoked')).not.toBeNull();
    expect(container.textContent).toContain('Credential Revoked');
    expect(container.querySelectorAll('.credential-field')).toHaveLength(0);
  });

  it('Promise.allSettled: registry and revocation fetched in parallel', async () => {
    const params = makeSignedParams(secretKey);
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        search: `?p=${params.payload}&s=${params.signature}`,
        hostname: 'localhost',
      },
      writable: true,
      configurable: true,
    });

    let registryFetchTime = 0;
    let revocationFetchTime = 0;
    const startTime = Date.now();

    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      if (url.includes('registry.json')) {
        registryFetchTime = Date.now() - startTime;
        return Promise.resolve(new Response(makeRegistryJson(registry), { status: 200 }));
      }
      if (url.includes('revocations.json')) {
        revocationFetchTime = Date.now() - startTime;
        return Promise.resolve(
          new Response(makeRevocationListJson(makeEmptyRevocationList()), { status: 200 }),
        );
      }
      return Promise.reject(new Error(`Unexpected URL: ${url}`));
    });

    await initVerifyPage();

    // Both fetches should be initiated at approximately the same time (parallel)
    // In a synchronous mock environment, both will be ~0ms from start
    expect(Math.abs(registryFetchTime - revocationFetchTime)).toBeLessThan(50);
    // Verify both were actually called
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// Cross-system hash consistency
// ---------------------------------------------------------------------------

describe('SHA-256 hash consistency', () => {
  it('SHA-256 hash of canonical payload matches expected hex string', async () => {
    const payload = new TextEncoder().encode(
      '{"date":"2024-06-15","detail":"Test Detail","honor":"Test Honor","recipient":"Jane Doe","version":1}',
    );
    const expected = createHash('sha256').update(payload).digest('hex');

    // Compute via crypto.subtle (which is what the browser uses)
    const hashBuffer = await crypto.subtle.digest('SHA-256', payload);
    const actual = [...new Uint8Array(hashBuffer)]
      .map(b => b.toString(16).padStart(2, '0')).join('');

    expect(actual).toBe(expected);
  });
});
