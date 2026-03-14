/**
 * Browser entry point for the credential issuer interface.
 *
 * Bundled by esbuild into `issuer/issuer.js` (IIFE format). Handles
 * authentication, form submission, QR code rendering, and download/copy
 * actions. All text is set via `textContent` to prevent XSS.
 */

import QRCode from 'qrcode';
import {
  DOM_IDS,
  HONOR_TITLES,
  QR_VERSION,
  QR_PREVIEW_WIDTH,
  QR_RENDER_WIDTH,
  QR_QUIET_ZONE,
  QR_PRINT_MIN_CM,
  QR_PRINT_REC_CM,
  validateFormFields,
  computeUrlLength,
  formatSignError,
} from './issuer.js';

import type { FormFields } from './issuer.js';
import type { SignResponse } from './server/sign.js';

// ---------------------------------------------------------------------------
// Module-scoped state (NOT in sessionStorage)
// ---------------------------------------------------------------------------

let storedToken: string | null = null;
let authority = '';
let downloadCanvas: HTMLCanvasElement | null = null;
let precomputedHash: string | null = null;
let statusTimeout: ReturnType<typeof setTimeout> | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Non-cryptographic hash — used only for download filename when crypto.subtle is unavailable. */
function djb2FallbackHash(str: string): string {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) | 0;
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/** Compute first 8 hex chars of SHA-256 of a string, with DJB2 fallback. */
async function computePayloadHash(payload: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle?.digest) {
    const data = new TextEncoder().encode(payload);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 8);
  }
  return djb2FallbackHash(payload);
}

/** Get today's date in YYYY-MM-DD format. */
function todayString(): string {
  const d = new Date();
  const year = d.getFullYear().toString().padStart(4, '0');
  const month = (d.getMonth() + 1).toString().padStart(2, '0');
  const day = d.getDate().toString().padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** Get a DOM element by ID or throw. */
function getEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

/** Show an error in the error banner. */
function showError(message: string): void {
  const banner = getEl(DOM_IDS.ERROR_BANNER);
  banner.textContent = message;
  banner.style.display = 'block';
}

/** Hide the error banner. */
function hideError(): void {
  const banner = getEl(DOM_IDS.ERROR_BANNER);
  banner.textContent = '';
  banner.style.display = 'none';
}

/** Show a status message. */
function showStatus(message: string): void {
  const el = getEl(DOM_IDS.STATUS_MESSAGE);
  el.textContent = message;
  el.style.display = 'block';
}

/** Hide the status message. */
function hideStatus(): void {
  const el = getEl(DOM_IDS.STATUS_MESSAGE);
  el.textContent = '';
  el.style.display = 'none';
}

// ---------------------------------------------------------------------------
// DOM construction
// ---------------------------------------------------------------------------

/** Build the full issuer UI inside the app container. */
function buildUI(app: HTMLElement): void {
  app.textContent = '';

  // Error banner
  const errorBanner = document.createElement('div');
  errorBanner.id = DOM_IDS.ERROR_BANNER;
  errorBanner.className = 'error-banner';
  errorBanner.style.display = 'none';
  app.appendChild(errorBanner);

  // Status message
  const statusMsg = document.createElement('div');
  statusMsg.id = DOM_IDS.STATUS_MESSAGE;
  statusMsg.className = 'status-message';
  statusMsg.style.display = 'none';
  app.appendChild(statusMsg);

  // Auth section
  const authSection = document.createElement('section');
  authSection.id = DOM_IDS.AUTH_SECTION;
  const authLabel = document.createElement('label');
  authLabel.textContent = 'Authentication Token';
  authLabel.setAttribute('for', DOM_IDS.TOKEN_INPUT);
  authSection.appendChild(authLabel);
  const tokenInput = document.createElement('input');
  tokenInput.id = DOM_IDS.TOKEN_INPUT;
  tokenInput.type = 'password';
  tokenInput.autocomplete = 'off';
  authSection.appendChild(tokenInput);
  const tokenBtn = document.createElement('button');
  tokenBtn.id = DOM_IDS.TOKEN_SUBMIT;
  tokenBtn.type = 'button';
  tokenBtn.textContent = 'Authenticate';
  authSection.appendChild(tokenBtn);
  app.appendChild(authSection);

  // Form section (hidden initially)
  const form = document.createElement('form');
  form.id = DOM_IDS.FORM;
  form.style.display = 'none';

  // Recipient
  const recipientLabel = document.createElement('label');
  recipientLabel.textContent = 'Recipient';
  recipientLabel.setAttribute('for', DOM_IDS.RECIPIENT_INPUT);
  form.appendChild(recipientLabel);
  const recipientInput = document.createElement('input');
  recipientInput.id = DOM_IDS.RECIPIENT_INPUT;
  recipientInput.type = 'text';
  recipientInput.required = true;
  form.appendChild(recipientInput);

  // Honor select
  const honorLabel = document.createElement('label');
  honorLabel.textContent = 'Honor';
  honorLabel.setAttribute('for', DOM_IDS.HONOR_SELECT);
  form.appendChild(honorLabel);
  const honorSelect = document.createElement('select');
  honorSelect.id = DOM_IDS.HONOR_SELECT;
  honorSelect.required = true;
  const defaultOpt = document.createElement('option');
  defaultOpt.value = '';
  defaultOpt.textContent = 'Select an honor...';
  honorSelect.appendChild(defaultOpt);
  for (const title of HONOR_TITLES) {
    const opt = document.createElement('option');
    opt.value = title;
    opt.textContent = title;
    honorSelect.appendChild(opt);
  }
  form.appendChild(honorSelect);

  // Detail
  const detailLabel = document.createElement('label');
  detailLabel.textContent = 'Detail';
  detailLabel.setAttribute('for', DOM_IDS.DETAIL_INPUT);
  form.appendChild(detailLabel);
  const detailInput = document.createElement('textarea');
  detailInput.id = DOM_IDS.DETAIL_INPUT;
  detailInput.required = true;
  form.appendChild(detailInput);

  // Date
  const dateLabel = document.createElement('label');
  dateLabel.textContent = 'Date';
  dateLabel.setAttribute('for', DOM_IDS.DATE_INPUT);
  form.appendChild(dateLabel);
  const dateInput = document.createElement('input');
  dateInput.id = DOM_IDS.DATE_INPUT;
  dateInput.type = 'date';
  dateInput.required = true;
  dateInput.value = todayString();
  form.appendChild(dateInput);

  // Submit
  const submitBtn = document.createElement('button');
  submitBtn.id = DOM_IDS.FORM_SUBMIT;
  submitBtn.type = 'submit';
  submitBtn.textContent = 'Sign Credential';
  form.appendChild(submitBtn);
  app.appendChild(form);

  // Result section (hidden initially)
  const resultSection = document.createElement('section');
  resultSection.id = DOM_IDS.RESULT_SECTION;
  resultSection.style.display = 'none';
  app.appendChild(resultSection);
}

// ---------------------------------------------------------------------------
// Auth flow
// ---------------------------------------------------------------------------

async function handleTokenSubmit(): Promise<void> {
  hideError();
  const tokenInput = getEl<HTMLInputElement>(DOM_IDS.TOKEN_INPUT);
  const token = tokenInput.value.trim();
  if (!token) {
    showError('Please enter a token');
    return;
  }

  let response: Response;
  try {
    response = await fetch(`${window.location.origin}/health`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    showError('Cannot reach server');
    return;
  }

  if (!response.ok) {
    showError('Authentication failed — invalid token');
    return;
  }

  let body: { authenticated?: boolean; authority?: string };
  try {
    body = await response.json();
  } catch {
    showError('Invalid server response');
    return;
  }

  if (!body.authenticated) {
    showError('Authentication failed — invalid token');
    return;
  }

  // Extract authority from authenticated health response
  authority = body.authority ?? '';
  const subtitle = document.querySelector('.subtitle');
  if (subtitle && authority) {
    subtitle.textContent = `Credential Issuance — ${authority}`;
  }

  storedToken = token;
  const authSection = getEl(DOM_IDS.AUTH_SECTION);
  authSection.style.display = 'none';
  const form = getEl(DOM_IDS.FORM);
  form.style.display = 'block';
}

// ---------------------------------------------------------------------------
// Sign flow
// ---------------------------------------------------------------------------

/** Read form fields from the DOM. */
function readFormFields(): FormFields {
  return {
    recipient: getEl<HTMLInputElement>(DOM_IDS.RECIPIENT_INPUT).value,
    honor: getEl<HTMLSelectElement>(DOM_IDS.HONOR_SELECT).value,
    detail: getEl<HTMLTextAreaElement>(DOM_IDS.DETAIL_INPUT).value,
    date: getEl<HTMLInputElement>(DOM_IDS.DATE_INPUT).value,
  };
}

async function handleFormSubmit(e: Event): Promise<void> {
  e.preventDefault();
  hideError();
  hideStatus();

  const fields = readFormFields();

  // Validate
  const validationError = validateFormFields(fields);
  if (validationError) {
    showError(validationError);
    return;
  }

  // Check URL length
  const urlCheck = computeUrlLength(fields, authority);
  if (!urlCheck.fits) {
    showError(`Credential URL too long: ${urlCheck.estimatedLength}/${urlCheck.maxLength} characters`);
    return;
  }

  const submitBtn = getEl<HTMLButtonElement>(DOM_IDS.FORM_SUBMIT);
  submitBtn.disabled = true;
  showStatus('Waiting for YubiKey...');

  try {
    let response: Response;
    try {
      response = await fetch(`${window.location.origin}/sign`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${storedToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          recipient: fields.recipient,
          honor: fields.honor,
          detail: fields.detail,
          date: fields.date,
        }),
      });
    } catch {
      showError('Cannot reach server');
      return;
    }

    if (response.status === 401) {
      storedToken = null;
      const authSection = getEl(DOM_IDS.AUTH_SECTION);
      authSection.style.display = 'block';
      const form = getEl(DOM_IDS.FORM);
      form.style.display = 'none';
      showError('Authentication expired — please re-enter your token');
      // Preserve form values: they remain in DOM, hidden but not cleared
      return;
    }

    if (!response.ok) {
      let body: { error?: string; code?: string } | undefined;
      try {
        body = await response.json();
      } catch {
        body = undefined;
      }
      showError(formatSignError(response.status, body));
      return;
    }

    let signResult: SignResponse;
    try {
      signResult = await response.json();
    } catch {
      showError('Invalid server response');
      return;
    }

    // Pre-compute hash eagerly
    precomputedHash = await computePayloadHash(signResult.payload);

    await renderSignResult(signResult, fields);
  } finally {
    submitBtn.disabled = false;
    hideStatus();
  }
}

// ---------------------------------------------------------------------------
// QR rendering and result display
// ---------------------------------------------------------------------------

async function renderSignResult(result: SignResponse, fields: FormFields): Promise<void> {
  const resultSection = getEl(DOM_IDS.RESULT_SECTION);
  resultSection.textContent = '';
  resultSection.style.display = 'block';

  // Credential summary
  const summary = document.createElement('div');
  summary.className = 'credential-summary';
  const summaryFields: Array<[string, string]> = [
    ['Recipient', fields.recipient],
    ['Honor', fields.honor],
    ['Detail', fields.detail],
    ['Date', fields.date],
  ];
  for (const [label, value] of summaryFields) {
    const row = document.createElement('div');
    row.className = 'summary-field';
    const labelEl = document.createElement('span');
    labelEl.className = 'field-label';
    labelEl.textContent = label;
    const valueEl = document.createElement('span');
    valueEl.className = 'field-value';
    valueEl.textContent = value;
    row.appendChild(labelEl);
    row.appendChild(valueEl);
    summary.appendChild(row);
  }
  resultSection.appendChild(summary);

  // QR preview canvas
  const previewCanvas = document.createElement('canvas');
  previewCanvas.id = DOM_IDS.QR_PREVIEW;
  resultSection.appendChild(previewCanvas);

  try {
    await QRCode.toCanvas(previewCanvas, result.url, {
      errorCorrectionLevel: 'Q',
      version: QR_VERSION,
      width: QR_PREVIEW_WIDTH,
      margin: QR_QUIET_ZONE,
    });
  } catch (err) {
    showError(`QR code generation failed: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  // Print advisory
  const advisory = document.createElement('p');
  advisory.className = 'print-advisory';
  advisory.textContent = `Print size: minimum ${QR_PRINT_MIN_CM} \u00d7 ${QR_PRINT_MIN_CM} cm (2.4 \u00d7 2.4 in). Recommended: ${QR_PRINT_REC_CM} \u00d7 ${QR_PRINT_REC_CM} cm (2.9 \u00d7 2.9 in).`;
  resultSection.appendChild(advisory);

  // Action buttons
  const actions = document.createElement('div');
  actions.id = DOM_IDS.QR_ACTIONS;

  const downloadBtn = document.createElement('button');
  downloadBtn.type = 'button';
  downloadBtn.textContent = 'Download QR';
  downloadBtn.addEventListener('click', () => handleDownload(result));
  actions.appendChild(downloadBtn);

  const copyBtn = document.createElement('button');
  copyBtn.type = 'button';
  copyBtn.textContent = 'Copy URL';
  copyBtn.addEventListener('click', () => handleCopyUrl(result.url, actions));
  actions.appendChild(copyBtn);

  resultSection.appendChild(actions);
}

async function handleDownload(result: SignResponse): Promise<void> {
  try {
    if (!downloadCanvas) {
      downloadCanvas = document.createElement('canvas');
    }
    await QRCode.toCanvas(downloadCanvas, result.url, {
      errorCorrectionLevel: 'Q',
      version: QR_VERSION,
      width: QR_RENDER_WIDTH,
      margin: QR_QUIET_ZONE,
    });
    const dataUrl = downloadCanvas.toDataURL('image/png');
    const hash = precomputedHash ?? djb2FallbackHash(result.payload);
    const filename = `rhg-credential-${readFormFields().date}-${hash}.png`;
    const link = document.createElement('a');
    link.href = dataUrl;
    link.download = filename;
    link.click();
  } catch (err) {
    showError(`QR download failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function handleCopyUrl(url: string, container: HTMLElement): Promise<void> {
  try {
    if (!navigator.clipboard) {
      throw new Error('Clipboard API unavailable');
    }
    await navigator.clipboard.writeText(url);
    showStatus('URL copied to clipboard');
    if (statusTimeout !== null) clearTimeout(statusTimeout);
    statusTimeout = setTimeout(hideStatus, 2000);
  } catch {
    // Fallback: show selectable text field
    const existing = container.querySelector('.copy-fallback');
    if (existing) existing.remove();
    const input = document.createElement('input');
    input.className = 'copy-fallback';
    input.type = 'text';
    input.readOnly = true;
    input.value = url;
    container.appendChild(input);
    input.select();
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/** Main entry point — called on DOMContentLoaded. */
export async function initIssuerPage(): Promise<void> {
  const app = document.getElementById(DOM_IDS.APP);
  if (!app) {
    console.error('Missing #app container');
    return;
  }

  buildUI(app);

  // Health check (no auth)
  let healthOk = false;
  try {
    const response = await fetch(`${window.location.origin}/health`);
    if (response.ok) {
      healthOk = true;
    } else {
      showError('Server returned an error');
    }
  } catch {
    showError('Server is offline — cannot connect');
  }

  if (!healthOk) return;

  // Wire up auth
  const tokenBtn = getEl(DOM_IDS.TOKEN_SUBMIT);
  tokenBtn.addEventListener('click', handleTokenSubmit);
  const tokenInput = getEl<HTMLInputElement>(DOM_IDS.TOKEN_INPUT);
  tokenInput.addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Enter') handleTokenSubmit();
  });

  // Wire up form
  const form = getEl(DOM_IDS.FORM);
  form.addEventListener('submit', handleFormSubmit);
}

// Exported for testing — reset module state
export function _resetState(): void {
  storedToken = null;
  authority = '';
  downloadCanvas = null;
  precomputedHash = null;
  if (statusTimeout !== null) clearTimeout(statusTimeout);
  statusTimeout = null;
}

// Exported for testing — get/set stored token
export function _getStoredToken(): string | null {
  return storedToken;
}
export function _setStoredToken(token: string | null): void {
  storedToken = token;
}
export function _setAuthority(a: string): void {
  authority = a;
}

document.addEventListener('DOMContentLoaded', initIssuerPage);
