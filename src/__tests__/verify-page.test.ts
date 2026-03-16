// @vitest-environment happy-dom

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  parseParams,
  getRegistryUrl,
  fetchRegistry,
  runVerification,
  renderResult,
  initVerifyPage,
} from '../verify-page.js';
import { sign } from '../crypto.js';
import { canonicalize } from '../canonical.js';
import { base64urlEncode } from '../base64url.js';

import type { PageParams, VerifyPageResult } from '../verify-page.js';
import type { Registry } from '../registry.js';
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
// runVerification
// ---------------------------------------------------------------------------

describe('runVerification', () => {
  const { secretKey, publicKey } = makeKeypair();
  const entry = makeKeyEntry(publicKey);
  const registry = makeRegistry(entry);

  it('returns valid result with fields from payload and authority from registry key', () => {
    const params = makeSignedParams(secretKey);
    const result = runVerification(params, registry);
    expect(result).toEqual({
      status: 'valid',
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
      authority: 'Test Authority',
    });
  });

  it('returns invalid for tampered payload', () => {
    const params = makeSignedParams(secretKey);
    // Tamper the payload (change a character)
    const tamperedPayload = base64urlEncode(
      canonicalize(validCredentialObj({ recipient: 'Evil Eve' }) as Record<string, string | number>),
    );
    const result = runVerification(
      { payload: tamperedPayload, signature: params.signature },
      registry,
    );
    expect(result.status).toBe('invalid');
  });

  it('returns error for invalid Base64URL in p', () => {
    const result = runVerification(
      { payload: '!!!invalid!!!', signature: 'AAAA' },
      registry,
    );
    expect(result).toEqual({ status: 'error', message: 'Invalid credential encoding' });
  });

  it('returns error for invalid Base64URL in s', () => {
    const params = makeSignedParams(secretKey);
    const result = runVerification(
      { payload: params.payload, signature: '!!!invalid!!!' },
      registry,
    );
    expect(result).toEqual({ status: 'error', message: 'Invalid signature encoding' });
  });

  it('returns invalid for signature not exactly 64 bytes', () => {
    const params = makeSignedParams(secretKey);
    // Create a valid base64url string that decodes to 32 bytes instead of 64
    const shortSig = base64urlEncode(new Uint8Array(32));
    const result = runVerification(
      { payload: params.payload, signature: shortSig },
      registry,
    );
    // Signature length validated by verifyCredential, returns invalid (not error).
    expect(result).toEqual({ status: 'invalid', reason: 'invalid signature length' });
  });

  it('returns invalid with date-mismatch reason', () => {
    const restrictedEntry = makeKeyEntry(publicKey, { from: '2025-01-01', to: '2025-12-31' });
    const restrictedRegistry = makeRegistry(restrictedEntry);
    // Credential date is 2024-06-15, key valid from 2025
    const params = makeSignedParams(secretKey);
    const result = runVerification(params, restrictedRegistry);
    expect(result.status).toBe('invalid');
    expect((result as { status: 'invalid'; reason: string }).reason).toContain(
      'date outside key validity period',
    );
  });

  it('rejects payload with non-string field value', () => {
    // verifyCredential validates the credential schema before checking the signature,
    // so a non-string field is caught there first (returning 'invalid').
    // The L7 field type guard in runVerification is defense-in-depth for the
    // success path only.
    const badObj = { ...validCredentialObj(), recipient: 123 };
    const payloadBytes = canonicalize(badObj as Record<string, string | number>);
    const signatureBytes = sign(payloadBytes, secretKey);
    const params: PageParams = {
      payload: base64urlEncode(payloadBytes),
      signature: base64urlEncode(signatureBytes),
    };
    const result = runVerification(params, registry);
    expect(result.status).toBe('invalid');
  });

  it('returns invalid for completely garbled payload', () => {
    const badPayload = base64urlEncode(new TextEncoder().encode('not json {{'));
    const sig = base64urlEncode(new Uint8Array(64));
    const result = runVerification(
      { payload: badPayload, signature: sig },
      registry,
    );
    expect(result.status).toBe('invalid');
  });

  it('valid result authority comes from registry key, not credential payload', () => {
    // Credential has no authority field — authority is derived from the matching
    // registry key entry.  Use a custom authority on the registry key and verify
    // the result surfaces that value.
    const customEntry = makeKeyEntry(publicKey, { authority: 'Registry Authority Name' });
    const customRegistry = makeRegistry(customEntry);
    const params = makeSignedParams(secretKey);
    const result = runVerification(params, customRegistry);
    expect(result.status).toBe('valid');
    expect((result as { status: 'valid'; authority: string }).authority).toBe(
      'Registry Authority Name',
    );
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

  it('full happy path: valid result rendered', async () => {
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

    vi.mocked(fetch).mockResolvedValue(
      new Response(makeRegistryJson(registry), { status: 200 }),
    );

    await initVerifyPage();

    expect(container.querySelector('.result-valid')).not.toBeNull();
    expect(container.textContent).toContain('Jane Doe');
    expect(container.textContent).toContain('Verified');
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

    vi.mocked(fetch).mockResolvedValue(
      new Response(makeRegistryJson(otherRegistry), { status: 200 }),
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

    vi.mocked(fetch).mockResolvedValue(
      new Response(makeRegistryJson(registry), { status: 200 }),
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

    vi.mocked(fetch).mockResolvedValue(
      new Response(makeRegistryJson(registry), { status: 200 }),
    );

    await initVerifyPage();

    expect(document.querySelector('.dev-warning')).toBeNull();
  });
});
