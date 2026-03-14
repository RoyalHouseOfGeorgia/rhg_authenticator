// @vitest-environment happy-dom

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  initIssuerPage,
  _resetState,
  _getStoredToken,
  _setStoredToken,
  _setAuthority,
} from '../issuer-page.js';
import { DOM_IDS, HONOR_TITLES } from '../issuer.js';
import { sign } from '../crypto.js';
import { canonicalize } from '../canonical.js';
import { base64urlEncode, base64urlDecode } from '../base64url.js';
import { verifyCredential } from '../verify.js';
import { handleSign } from '../server/sign.js';
import {
  makeKeypair,
  makeKeyEntry,
  makeRegistry,
  validCredentialObj,
} from './helpers.js';

import type { SigningAdapter } from '../server/types.js';

// ---------------------------------------------------------------------------
// Mock QRCode (happy-dom has no real canvas)
// ---------------------------------------------------------------------------

vi.mock('qrcode', () => ({
  default: {
    toCanvas: vi.fn().mockResolvedValue(undefined),
  },
}));

import QRCode from 'qrcode';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ORIGIN = 'http://localhost:3141';

function setupDOM(): void {
  document.body.innerHTML = `
    <header><p class="subtitle"></p></header>
    <main id="app"><noscript></noscript></main>
    <footer></footer>
  `;
}

function healthResponse(
  overrides: Record<string, unknown> = {},
  status = 200,
): Response {
  return new Response(
    JSON.stringify({ status: 'ok', ...overrides }),
    { status },
  );
}

function authHealthResponse(authenticated: boolean, status = 200): Response {
  return new Response(
    JSON.stringify({ authority: 'Test Authority', authenticated }),
    { status },
  );
}

function signResponse(
  overrides: Partial<{ signature: string; payload: string; url: string; warning: string }> = {},
): Response {
  return new Response(
    JSON.stringify({
      signature: 'sig123',
      payload: 'pay123',
      url: 'https://verify.royalhouseofgeorgia.ge/?p=pay123&s=sig123',
      ...overrides,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

function fillForm(fields?: Partial<{ recipient: string; honor: string; detail: string; date: string }>): void {
  const f = {
    recipient: 'Jane Doe',
    honor: HONOR_TITLES[0],
    detail: 'For service',
    date: '2026-03-13',
    ...fields,
  };
  (document.getElementById(DOM_IDS.RECIPIENT_INPUT) as HTMLInputElement).value = f.recipient;
  (document.getElementById(DOM_IDS.HONOR_SELECT) as HTMLSelectElement).value = f.honor;
  (document.getElementById(DOM_IDS.DETAIL_INPUT) as HTMLTextAreaElement).value = f.detail;
  (document.getElementById(DOM_IDS.DATE_INPUT) as HTMLInputElement).value = f.date;
}

async function authenticateUser(): Promise<void> {
  // First call = health check, second = auth health
  vi.mocked(fetch)
    .mockResolvedValueOnce(healthResponse())
    .mockResolvedValueOnce(authHealthResponse(true));

  await initIssuerPage();

  const tokenInput = document.getElementById(DOM_IDS.TOKEN_INPUT) as HTMLInputElement;
  tokenInput.value = 'test-token';
  const tokenBtn = document.getElementById(DOM_IDS.TOKEN_SUBMIT) as HTMLButtonElement;
  tokenBtn.click();
  // Let the async handler complete
  await vi.waitFor(() => {
    expect(document.getElementById(DOM_IDS.FORM)!.style.display).toBe('block');
  });
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn());
  Object.defineProperty(window, 'location', {
    value: { ...window.location, origin: ORIGIN, hostname: 'localhost' },
    writable: true,
    configurable: true,
  });
  setupDOM();
  _resetState();
  vi.mocked(QRCode.toCanvas).mockReset().mockResolvedValue(undefined as never);
});

afterEach(() => {
  document.body.innerHTML = '';
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Page initialization
// ---------------------------------------------------------------------------

describe('page initialization', () => {
  it('does not display authority in subtitle on unauthenticated health check', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();
    const subtitle = document.querySelector('.subtitle');
    expect(subtitle!.textContent).not.toContain('Test Authority');
    expect(subtitle!.textContent).toBe('');
  });

  it('shows error banner on health check HTTP error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 500 }));
    await initIssuerPage();
    const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
    expect(banner!.style.display).toBe('block');
    expect(banner!.textContent).toContain('error');
  });

  it('shows offline banner on network failure', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError('Network failure'));
    await initIssuerPage();
    const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
    expect(banner!.style.display).toBe('block');
    expect(banner!.textContent).toContain('offline');
  });

  it('pre-fills date input with today', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();
    const dateInput = document.getElementById(DOM_IDS.DATE_INPUT) as HTMLInputElement;
    expect(dateInput.value).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('unauthenticated health returns no authority (subtitle unchanged)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();
    const subtitle = document.querySelector('.subtitle');
    expect(subtitle!.textContent).toBe('');
  });

  it('does not show form or result sections initially', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();
    expect(document.getElementById(DOM_IDS.FORM)!.style.display).toBe('none');
    expect(document.getElementById(DOM_IDS.RESULT_SECTION)!.style.display).toBe('none');
  });
});

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

describe('token validation', () => {
  it('stores token and shows form on successful auth', async () => {
    await authenticateUser();
    expect(_getStoredToken()).toBe('test-token');
    expect(document.getElementById(DOM_IDS.AUTH_SECTION)!.style.display).toBe('none');
    expect(document.getElementById(DOM_IDS.FORM)!.style.display).toBe('block');
  });

  it('shows error on 401 from auth health check', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(healthResponse())
      .mockResolvedValueOnce(new Response('', { status: 401 }));
    await initIssuerPage();

    const tokenInput = document.getElementById(DOM_IDS.TOKEN_INPUT) as HTMLInputElement;
    tokenInput.value = 'bad-token';
    document.getElementById(DOM_IDS.TOKEN_SUBMIT)!.click();

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('failed');
    });
    expect(_getStoredToken()).toBeNull();
  });

  it('shows error on auth response with authenticated: false', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(healthResponse())
      .mockResolvedValueOnce(authHealthResponse(false));
    await initIssuerPage();

    const tokenInput = document.getElementById(DOM_IDS.TOKEN_INPUT) as HTMLInputElement;
    tokenInput.value = 'bad-token';
    document.getElementById(DOM_IDS.TOKEN_SUBMIT)!.click();

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('failed');
    });
  });

  it('shows error when token input is empty', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();

    document.getElementById(DOM_IDS.TOKEN_SUBMIT)!.click();

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('enter a token');
    });
  });

  it('hides auth section and shows form after auth success', async () => {
    await authenticateUser();
    expect(document.getElementById(DOM_IDS.AUTH_SECTION)!.style.display).toBe('none');
    expect(document.getElementById(DOM_IDS.FORM)!.style.display).toBe('block');
  });

  it('sets authority and subtitle after token submit', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(healthResponse())
      .mockResolvedValueOnce(authHealthResponse(true));
    await initIssuerPage();

    const tokenInput = document.getElementById(DOM_IDS.TOKEN_INPUT) as HTMLInputElement;
    tokenInput.value = 'test-token';
    document.getElementById(DOM_IDS.TOKEN_SUBMIT)!.click();

    await vi.waitFor(() => {
      const subtitle = document.querySelector('.subtitle');
      expect(subtitle!.textContent).toContain('Test Authority');
    });
  });

  it('computeUrlLength uses authority from authenticated health response', async () => {
    await authenticateUser();
    fillForm();

    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    // The sign call should have been made (no URL-too-long error),
    // confirming computeUrlLength used the correct authority value
    await vi.waitFor(() => {
      const signCalls = vi.mocked(fetch).mock.calls.filter((c) => (c[0] as string).includes('/sign'));
      expect(signCalls).toHaveLength(1);
    });
  });
});

// ---------------------------------------------------------------------------
// Token re-entry after 401 from /sign
// ---------------------------------------------------------------------------

describe('token re-entry after 401', () => {
  it('clears token, shows auth, preserves form values on 401 from /sign', async () => {
    await authenticateUser();
    fillForm({ recipient: 'Keep Me' });

    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 401 }));

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(_getStoredToken()).toBeNull();
    });

    expect(document.getElementById(DOM_IDS.AUTH_SECTION)!.style.display).toBe('block');
    // Form values preserved (form is hidden but values intact)
    expect((document.getElementById(DOM_IDS.RECIPIENT_INPUT) as HTMLInputElement).value).toBe('Keep Me');
  });
});

// ---------------------------------------------------------------------------
// Form submit
// ---------------------------------------------------------------------------

describe('form submit', () => {
  it('sends correct headers, body, and origin to /sign', async () => {
    await authenticateUser();
    fillForm();

    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(vi.mocked(fetch)).toHaveBeenCalledWith(
        `${ORIGIN}/sign`,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer test-token',
            'Content-Type': 'application/json',
          }),
        }),
      );
    });

    // Verify body
    const callArgs = vi.mocked(fetch).mock.calls.find((c) => (c[0] as string).includes('/sign'));
    const bodyObj = JSON.parse(callArgs![1]!.body as string);
    expect(bodyObj.recipient).toBe('Jane Doe');
    expect(bodyObj.honor).toBe(HONOR_TITLES[0]);
    expect(bodyObj.detail).toBe('For service');
    expect(bodyObj.date).toBe('2026-03-13');
  });

  it('shows validation error and does not call /sign', async () => {
    await authenticateUser();
    fillForm({ recipient: '' });

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('Recipient');
    });

    // Should not have made any call beyond health+auth
    const signCalls = vi.mocked(fetch).mock.calls.filter((c) => (c[0] as string).includes('/sign'));
    expect(signCalls).toHaveLength(0);
  });

  it('blocks submit when URL exceeds capacity', async () => {
    await authenticateUser();
    fillForm({ detail: 'A'.repeat(1000) });

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('/625');
    });

    const signCalls = vi.mocked(fetch).mock.calls.filter((c) => (c[0] as string).includes('/sign'));
    expect(signCalls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Success flow
// ---------------------------------------------------------------------------

describe('success flow', () => {
  it('renders QR preview, summary, and action buttons on 200', async () => {
    await authenticateUser();
    fillForm();

    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.RESULT_SECTION)!.style.display).toBe('block');
    });

    // QR preview rendered
    expect(QRCode.toCanvas).toHaveBeenCalled();
    // Summary fields
    const resultSection = document.getElementById(DOM_IDS.RESULT_SECTION)!;
    expect(resultSection.textContent).toContain('Jane Doe');
    expect(resultSection.textContent).toContain(HONOR_TITLES[0]);
    // Action buttons
    expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    // Print advisory
    expect(resultSection.textContent).toContain('6.1');
    expect(resultSection.textContent).toContain('7.3');
  });
});

// ---------------------------------------------------------------------------
// Error flows
// ---------------------------------------------------------------------------

describe('error flows', () => {
  async function submitAndExpect(status: number, expectedText: string): Promise<void> {
    await authenticateUser();
    fillForm();

    const body = status === 401 ? '' : JSON.stringify({ error: 'test error' });
    vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { status }));

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain(expectedText);
    });
  }

  it('401 clears token and shows re-auth', async () => {
    await submitAndExpect(401, 'expired');
    expect(_getStoredToken()).toBeNull();
  });

  it('400 shows formatted error', async () => {
    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Bad recipient field' }), { status: 400 }),
    );
    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.ERROR_BANNER)!.textContent).toContain('Bad recipient field');
    });
  });

  it('403 shows access denied', async () => {
    await submitAndExpect(403, 'Access denied');
  });

  it('405 shows method not allowed', async () => {
    await submitAndExpect(405, 'Method not allowed');
  });

  it('408 shows timeout', async () => {
    await submitAndExpect(408, 'timed out');
  });

  it('413 shows payload too large', async () => {
    await submitAndExpect(413, 'Payload too large');
  });

  it('415 shows unsupported content type', async () => {
    await submitAndExpect(415, 'Unsupported content type');
  });

  it('429 shows rate limit', async () => {
    await submitAndExpect(429, 'Too many requests');
  });

  it('500 shows server error', async () => {
    await submitAndExpect(500, 'Server error');
  });

  it('network error on /sign shows error banner', async () => {
    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError('Network failure'));
    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.ERROR_BANNER)!.textContent).toContain('Cannot reach server');
    });
  });
});

// ---------------------------------------------------------------------------
// QR library rejection
// ---------------------------------------------------------------------------

describe('QR library rejection', () => {
  it('displays error when QRCode.toCanvas throws', async () => {
    await authenticateUser();
    fillForm();

    vi.mocked(QRCode.toCanvas).mockRejectedValueOnce(new Error('Canvas too small'));
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('QR code generation failed');
    });
  });
});

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

describe('clipboard', () => {
  it('copies URL on success', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    });

    const copyBtn = document.getElementById(DOM_IDS.QR_ACTIONS)!.querySelectorAll('button')[1];
    copyBtn.click();

    await vi.waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(
        'https://verify.royalhouseofgeorgia.ge/?p=pay123&s=sig123',
      );
    });
  });

  it('shows fallback text field when clipboard.writeText rejects', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('Denied'));
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    });

    const copyBtn = document.getElementById(DOM_IDS.QR_ACTIONS)!.querySelectorAll('button')[1];
    copyBtn.click();

    await vi.waitFor(() => {
      const fallback = document.querySelector('.copy-fallback') as HTMLInputElement;
      expect(fallback).not.toBeNull();
      expect(fallback.value).toContain('verify.royalhouseofgeorgia.ge');
    });
  });

  it('shows fallback when navigator.clipboard is undefined', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: undefined,
      writable: true,
      configurable: true,
    });

    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    });

    const copyBtn = document.getElementById(DOM_IDS.QR_ACTIONS)!.querySelectorAll('button')[1];
    copyBtn.click();

    await vi.waitFor(() => {
      expect(document.querySelector('.copy-fallback')).not.toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// XSS safety
// ---------------------------------------------------------------------------

describe('XSS safety', () => {
  it('source file contains zero innerHTML occurrences', () => {
    const src = readFileSync(resolve(__dirname, '..', 'issuer-page.ts'), 'utf-8');
    const matches = src.match(/innerHTML/g);
    expect(matches).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// sessionStorage.setItem never called
// ---------------------------------------------------------------------------

describe('sessionStorage', () => {
  it('never calls sessionStorage.setItem during full flow', async () => {
    const spy = vi.spyOn(window.sessionStorage, 'setItem');

    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.RESULT_SECTION)!.style.display).toBe('block');
    });

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Submit button disabled during signing
// ---------------------------------------------------------------------------

describe('submit button state', () => {
  it('disables submit during signing and re-enables on response', async () => {
    await authenticateUser();
    fillForm();

    let resolveSign!: (value: Response) => void;
    const signPromise = new Promise<Response>((r) => {
      resolveSign = r;
    });
    vi.mocked(fetch).mockReturnValueOnce(signPromise as Promise<Response>);

    const submitBtn = document.getElementById(DOM_IDS.FORM_SUBMIT) as HTMLButtonElement;
    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    // Button should be disabled while request is in flight
    await vi.waitFor(() => {
      expect(submitBtn.disabled).toBe(true);
    });

    // Resolve the request
    resolveSign(signResponse());

    await vi.waitFor(() => {
      expect(submitBtn.disabled).toBe(false);
    });
  });

  it('re-enables submit button on error response', async () => {
    await authenticateUser();
    fillForm();

    vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ error: 'test' }), { status: 500 }));

    const submitBtn = document.getElementById(DOM_IDS.FORM_SUBMIT) as HTMLButtonElement;
    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(submitBtn.disabled).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Integration: signing pipeline with real crypto
// ---------------------------------------------------------------------------

describe('integration — signing pipeline', () => {
  it('verifies a credential signed via handleSign', async () => {
    const { secretKey, publicKey } = makeKeypair(42);
    const entry = makeKeyEntry(publicKey);
    const registry = makeRegistry(entry);

    const mockAdapter: SigningAdapter = {
      exportPublicKey: vi.fn().mockResolvedValue(publicKey),
      signBytes: vi.fn(async (data: Uint8Array) => sign(data, secretKey)),
    };

    const tmpLogPath = '/tmp/test-issuance-log-' + Date.now() + '.json';

    const request = {
      recipient: 'Jane Doe',
      honor: 'Test Honor',
      detail: 'Test Detail',
      date: '2024-06-15',
    };

    const result = await handleSign(request, mockAdapter, publicKey, 'Test Authority', tmpLogPath);
    expect('url' in result).toBe(true);
    const signResult = result as { url: string; payload: string; signature: string };

    // Parse URL, extract p and s
    const url = new URL(signResult.url);
    const p = url.searchParams.get('p')!;
    const s = url.searchParams.get('s')!;

    const payloadBytes = base64urlDecode(p);
    const signatureBytes = base64urlDecode(s);

    const verification = verifyCredential(payloadBytes, signatureBytes, registry);
    expect(verification.valid).toBe(true);
    if (verification.valid) {
      expect(verification.credential.recipient).toBe('Jane Doe');
      expect(verification.credential.honor).toBe('Test Honor');
      expect(verification.key.authority).toBe('Test Authority');
    }
  });
});

// ---------------------------------------------------------------------------
// Honor select population
// ---------------------------------------------------------------------------

describe('honor select', () => {
  it('populates honor select with all HONOR_TITLES', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(healthResponse());
    await initIssuerPage();

    const select = document.getElementById(DOM_IDS.HONOR_SELECT) as HTMLSelectElement;
    // +1 for the default "Select an honor..." option
    expect(select.options).toHaveLength(HONOR_TITLES.length + 1);
    for (const title of HONOR_TITLES) {
      const option = Array.from(select.options).find((o) => o.value === title);
      expect(option).toBeDefined();
      expect(option!.textContent).toBe(title);
    }
  });
});

// ---------------------------------------------------------------------------
// Status message during signing
// ---------------------------------------------------------------------------

describe('status message', () => {
  it('shows YubiKey status during signing', async () => {
    await authenticateUser();
    fillForm();

    let resolveSign!: (value: Response) => void;
    const signPromise = new Promise<Response>((r) => {
      resolveSign = r;
    });
    vi.mocked(fetch).mockReturnValueOnce(signPromise as Promise<Response>);

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      const statusEl = document.getElementById(DOM_IDS.STATUS_MESSAGE);
      expect(statusEl!.textContent).toContain('YubiKey');
      expect(statusEl!.style.display).toBe('block');
    });

    resolveSign(signResponse());

    await vi.waitFor(() => {
      const statusEl = document.getElementById(DOM_IDS.STATUS_MESSAGE);
      expect(statusEl!.style.display).toBe('none');
    });
  });
});

// ---------------------------------------------------------------------------
// Missing #app container
// ---------------------------------------------------------------------------

describe('missing app container', () => {
  it('returns without error when #app is missing', async () => {
    document.body.innerHTML = '';
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await initIssuerPage();
    expect(spy).toHaveBeenCalledWith('Missing #app container');
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// handleDownload error path
// ---------------------------------------------------------------------------

describe('handleDownload error path', () => {
  it('shows error banner when QRCode.toCanvas rejects during download', async () => {
    await authenticateUser();
    fillForm();

    // First toCanvas call (preview) succeeds, second (download) rejects
    vi.mocked(QRCode.toCanvas)
      .mockResolvedValueOnce(undefined as never)
      .mockRejectedValueOnce(new Error('Render failed'));

    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    });

    const downloadBtn = document.getElementById(DOM_IDS.QR_ACTIONS)!.querySelectorAll('button')[0];
    downloadBtn.click();

    await vi.waitFor(() => {
      const banner = document.getElementById(DOM_IDS.ERROR_BANNER);
      expect(banner!.textContent).toContain('QR download failed');
    });
  });
});

// ---------------------------------------------------------------------------
// statusTimeout cleared on rapid copy clicks
// ---------------------------------------------------------------------------

describe('statusTimeout cleanup on rapid copy clicks', () => {
  it('clears previous timer when Copy URL is clicked rapidly', async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    await authenticateUser();
    fillForm();
    vi.mocked(fetch).mockResolvedValueOnce(signResponse());

    const form = document.getElementById(DOM_IDS.FORM) as HTMLFormElement;
    form.dispatchEvent(new Event('submit', { cancelable: true }));

    await vi.waitFor(() => {
      expect(document.getElementById(DOM_IDS.QR_ACTIONS)).not.toBeNull();
    });

    const copyBtn = document.getElementById(DOM_IDS.QR_ACTIONS)!.querySelectorAll('button')[1];

    // Click twice rapidly
    copyBtn.click();
    await vi.waitFor(() => {
      expect(writeText).toHaveBeenCalledTimes(1);
    });

    copyBtn.click();
    await vi.waitFor(() => {
      expect(writeText).toHaveBeenCalledTimes(2);
    });

    // Second click should have called clearTimeout to cancel the first timer
    expect(clearTimeoutSpy).toHaveBeenCalled();
    clearTimeoutSpy.mockRestore();
  });
});
