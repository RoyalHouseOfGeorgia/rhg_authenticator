/**
 * Verification page logic for the credential verifier UI.
 *
 * Parses URL parameters, fetches the key registry, runs cryptographic
 * verification, and renders the result into the DOM. All text is set via
 * `textContent` to prevent XSS.
 */

import { base64urlDecode } from './base64url.js';
import { verifyCredential } from './verify.js';
import { validateRegistry } from './registry.js';

import type { Registry } from './registry.js';

export type PageParams = {
  payload: string;
  signature: string;
};

export type ParseError = {
  error: string;
};

export type VerifyPageResult =
  | { status: 'valid'; recipient: string; honor: string; detail: string; date: string; authority: string }
  | { status: 'info' }
  | { status: 'invalid'; reason: string }
  | { status: 'error'; message: string };

/**
 * Parse query string parameters for the verification page.
 *
 * Expects `p` (payload) and `s` (signature) parameters. Returns raw strings;
 * Base64URL decoding happens in `runVerification`.
 */
export function parseParams(search: string): PageParams | ParseError {
  const params = new URLSearchParams(search);

  const p = params.get('p');
  const s = params.get('s');

  if (p === null) {
    return { error: 'Missing credential data (p parameter)' };
  }
  if (s === null) {
    return { error: 'Missing signature (s parameter)' };
  }
  if (p === '') {
    return { error: 'Empty credential data (p parameter)' };
  }
  if (s === '') {
    return { error: 'Empty signature (s parameter)' };
  }

  return { payload: p, signature: s };
}

/** The production hostname for the verification page.
 *  Must match the connect-src in verify/index.html CSP meta tag. */
const PRODUCTION_HOSTNAME = 'verify.royalhouseofgeorgia.ge';

/**
 * Determine the registry URL based on the current hostname.
 *
 * Returns the absolute production URL only when running on the production
 * hostname. All other hostnames (localhost, LAN IPs, dev servers) use a
 * relative path so the registry is fetched from the same origin.
 */
export function getRegistryUrl(): string {
  const hostname = window.location.hostname;
  if (hostname === PRODUCTION_HOSTNAME) {
    return `https://${PRODUCTION_HOSTNAME}/keys/registry.json`;
  }
  return '/keys/registry.json';
}

/** Timeout in milliseconds for the registry fetch. */
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Fetch and validate the key registry from the given URL.
 *
 * Uses an `AbortController` with a 10-second timeout. Throws a user-facing
 * error string on all failure conditions.
 */
export async function fetchRegistry(url: string): Promise<Registry> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
  } catch (err) {
    throw new Error('Failed to contact verification service', { cause: err });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error('Verification service returned an error');
  }

  const MAX_REGISTRY_BYTES = 1 << 20; // 1 MiB

  // Early-out on Content-Length (optimization only — may reflect compressed size).
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && parseInt(contentLength, 10) > MAX_REGISTRY_BYTES) {
    throw new Error('Registry response exceeds size limit');
  }

  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_REGISTRY_BYTES) {
    throw new Error('Registry response exceeds size limit');
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch (err) {
    throw new Error('Registry data is corrupted', { cause: err });
  }

  try {
    return validateRegistry(body);
  } catch (err) {
    throw new Error('Registry data is invalid', { cause: err });
  }
}

/**
 * Decode Base64URL parameters, verify the credential, and return a typed result.
 *
 * The `authority` in a valid result comes from the registry key entry, not the
 * credential payload, preventing forged authority names from reaching the UI.
 */
export function runVerification(params: PageParams, registry: Registry): VerifyPageResult {
  let payloadBytes: Uint8Array;
  try {
    payloadBytes = base64urlDecode(params.payload);
  } catch {
    return { status: 'error', message: 'Invalid credential encoding' };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64urlDecode(params.signature);
  } catch {
    return { status: 'error', message: 'Invalid signature encoding' };
  }

  if (signatureBytes.length !== 64) {
    return { status: 'error', message: 'Invalid signature length' };
  }

  const result = verifyCredential(payloadBytes, signatureBytes, registry);

  if (result.valid) {
    return {
      status: 'valid',
      recipient: result.credential.recipient,
      honor: result.credential.honor,
      detail: result.credential.detail,
      date: result.credential.date,
      authority: result.key.authority,
    };
  }

  return { status: 'invalid', reason: result.reason };
}

/** Build the contact-info paragraph with mailto link used in error/invalid states. */
function createContactParagraph(): HTMLParagraphElement {
  const contact = document.createElement('p');
  contact.className = 'contact-info';
  contact.appendChild(document.createTextNode('If you believe this is in error, please contact the Office of the Secretary of the Royal House of Georgia at '));
  const mailto = document.createElement('a');
  mailto.className = 'contact-link';
  mailto.textContent = 'secretary@royalhouseofgeorgia.ge';
  mailto.setAttribute('href', 'mailto:secretary@royalhouseofgeorgia.ge');
  contact.appendChild(mailto);
  contact.appendChild(document.createTextNode('.'));
  return contact;
}

/**
 * Render a verification result into the given DOM container.
 *
 * All text is set via `textContent` (never `innerHTML`) to prevent XSS.
 * Each state has a color indicator and a text label with icon for WCAG AA
 * accessibility (not relying on color alone).
 */
export function renderResult(result: VerifyPageResult, container: Element): void {
  container.textContent = '';

  const wrapper = document.createElement('div');

  switch (result.status) {
    case 'valid': {
      wrapper.className = 'result-valid';

      const banner = document.createElement('div');
      banner.className = 'status-banner';
      banner.textContent = 'Verified';
      wrapper.appendChild(banner);

      const fields: Array<[string, string]> = [
        ['Recipient', result.recipient],
        ['Honor', result.honor],
        ['Detail', result.detail],
        ['Date', result.date],
        ['Authority', result.authority],
      ];

      for (const [label, value] of fields) {
        const row = document.createElement('div');
        row.className = 'credential-field';
        const labelEl = document.createElement('span');
        labelEl.className = 'field-label';
        labelEl.textContent = label;
        const valueEl = document.createElement('span');
        valueEl.className = 'field-value';
        valueEl.textContent = value;
        row.appendChild(labelEl);
        row.appendChild(valueEl);
        wrapper.appendChild(row);
      }
      break;
    }

    case 'info': {
      wrapper.className = 'result-info';

      const heading = document.createElement('h2');
      heading.className = 'info-heading';
      heading.textContent = 'Digital Credential Verification';
      wrapper.appendChild(heading);

      const body = document.createElement('p');
      body.className = 'info-text';
      body.textContent = 'This page verifies honors and credentials issued by the Royal House of Georgia. When a credential is presented (for example, via a QR code on a diploma), this page confirms its authenticity.';
      wrapper.appendChild(body);

      const link = document.createElement('a');
      link.className = 'info-link';
      link.textContent = 'Visit the Royal House of Georgia';
      link.setAttribute('href', 'https://royalhouseofgeorgia.ge');
      wrapper.appendChild(link);
      break;
    }

    case 'invalid': {
      wrapper.className = 'result-invalid';

      const banner = document.createElement('div');
      banner.className = 'status-banner';
      banner.textContent = 'Not Verified';
      wrapper.appendChild(banner);

      const detail = document.createElement('p');
      detail.className = 'result-detail';
      detail.textContent = 'This credential could not be verified. It may be invalid, tampered with, or not issued by the Royal House of Georgia.';
      wrapper.appendChild(detail);

      wrapper.appendChild(createContactParagraph());
      break;
    }

    case 'error': {
      wrapper.className = 'result-error';

      const banner = document.createElement('div');
      banner.className = 'status-banner';
      banner.textContent = 'Verification Error';
      wrapper.appendChild(banner);

      const detail = document.createElement('p');
      detail.className = 'result-detail';
      detail.textContent = 'We were unable to complete the verification. This may be due to a temporary issue or an invalid verification link.';
      wrapper.appendChild(detail);

      wrapper.appendChild(createContactParagraph());
      break;
    }

    default: {
      const _exhaustive: never = result;
      throw new Error(`Unexpected result status: ${(_exhaustive as { status: string }).status}`);
    }
  }

  container.appendChild(wrapper);
}

/**
 * Entry point for the verification page.
 *
 * Orchestrates parameter parsing, registry fetching, verification, and
 * rendering. Handles all error conditions gracefully.
 */
export async function initVerifyPage(): Promise<void> {
  const container = document.getElementById('result');
  if (!container) {
    console.error('Missing #result container');
    return;
  }

  // M3: Warn users when running on a non-production hostname
  if (window.location.hostname !== PRODUCTION_HOSTNAME) {
    if (container.parentElement) {
      const warning = document.createElement('div');
      warning.className = 'dev-warning';
      warning.textContent = 'Development mode — not the official verification page';
      container.before(warning);
    }
  }

  const paramResult = parseParams(window.location.search);
  if ('error' in paramResult) {
    renderResult({ status: 'info' }, container);
    return;
  }

  let registry: Registry;
  try {
    const url = getRegistryUrl();
    registry = await fetchRegistry(url);
  } catch (err) {
    renderResult({ status: 'error', message: (err as Error).message }, container);
    return;
  }

  const result = runVerification(paramResult, registry);
  renderResult(result, container);
}

document.addEventListener('DOMContentLoaded', () => initVerifyPage().catch(console.error));
