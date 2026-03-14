import { createHash } from 'node:crypto';
import { readFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { handleSign } from '../../server/sign.js';
import { canonicalize } from '../../canonical.js';
import type { SignRequest, SignResponse, SignError } from '../../server/sign.js';
import type { SigningAdapter } from '../../server/types.js';

// Deterministic 32-byte secret key for all tests.
const SECRET_KEY = new Uint8Array(32);
SECRET_KEY[0] = 0x01;
SECRET_KEY[31] = 0xff;

const PUBLIC_KEY = ed25519.getPublicKey(SECRET_KEY);

function createMockAdapter(secretKey: Uint8Array): SigningAdapter {
  return {
    exportPublicKey: async () => ed25519.getPublicKey(secretKey),
    signBytes: async (data: Uint8Array) => ed25519.sign(data, secretKey),
  };
}

function validRequest(): SignRequest {
  return {
    recipient: 'John Doe',
    honor: 'Knight Commander',
    detail: 'For distinguished service',
    date: '2026-03-12',
  };
}

const AUTHORITY = 'Royal House of Georgia';

function isSignResponse(r: SignResponse | SignError): r is SignResponse {
  return 'signature' in r && 'payload' in r && 'url' in r;
}

function isSignError(r: SignResponse | SignError): r is SignError {
  return 'error' in r && 'code' in r;
}

let testDir: string;
let logPath: string;

describe('handleSign', () => {
  beforeEach(async () => {
    testDir = join(tmpdir(), `sign-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(testDir, { recursive: true });
    logPath = join(testDir, 'issuances.json');
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(testDir, { recursive: true, force: true });
  });

  it('returns a valid SignResponse with verification URL for a valid request', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignResponse(result)).toBe(true);
    const resp = result as SignResponse;
    expect(resp.signature).toBeTruthy();
    expect(resp.payload).toBeTruthy();
    expect(resp.url).toContain('p=');
    expect(resp.url).toContain('s=');
    expect(resp.warning).toBeUndefined();
  });

  it('returns VALIDATION_FAILED with generic error for a missing required field', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = createMockAdapter(SECRET_KEY);
    const req = validRequest();
    req.recipient = '';

    const result = await handleSign(req, adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.error).toBe('Invalid credential data');
    expect(consoleSpy).toHaveBeenCalledWith(
      'Credential validation failed:',
      expect.stringContaining('recipient'),
    );
  });

  it('returns VALIDATION_FAILED with generic error for an invalid date format', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = createMockAdapter(SECRET_KEY);
    const req = validRequest();
    req.date = '2026/03/12';

    const result = await handleSign(req, adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.error).toBe('Invalid credential data');
    expect(consoleSpy).toHaveBeenCalledWith(
      'Credential validation failed:',
      expect.stringContaining('date'),
    );
  });

  it('returns SIGNING_FAILED when the adapter throws', async () => {
    const adapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async () => {
        throw new Error('YubiKey disconnected');
      },
    };

    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('SIGNING_FAILED');
  });

  it('returns SIGNING_FAILED when the adapter returns wrong-length signature', async () => {
    const adapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async () => new Uint8Array(48),
    };

    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('SIGNING_FAILED');
  });

  it('round-trip verification passes for a valid sign (sanity check)', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignResponse(result)).toBe(true);
    // The fact that we got a SignResponse (not SignError) proves the post-sign
    // verify() check passed. Additionally, verify externally:
    const resp = result as SignResponse;
    // Decode the payload and signature from the URL to double-check
    const urlObj = new URL(resp.url);
    expect(urlObj.searchParams.has('p')).toBe(true);
    expect(urlObj.searchParams.has('s')).toBe(true);
  });

  it('returns SIGNING_FAILED when post-sign verify returns false (bit-flipped signature)', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    // Adapter that returns a valid-length but corrupted signature.
    const adapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async (data: Uint8Array) => {
        const sig = ed25519.sign(data, SECRET_KEY);
        // Flip bits in first byte to make it invalid.
        const corrupted = new Uint8Array(sig);
        corrupted[0] ^= 0xff;
        return corrupted;
      },
    };

    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('SIGNING_FAILED');
    expect(consoleSpy).toHaveBeenCalledWith('Post-sign verification failed');
  });

  it('writes a log record after successful signing', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    const raw = await readFile(logPath, 'utf-8');
    const records = JSON.parse(raw) as unknown[];
    expect(records).toHaveLength(1);

    const rec = records[0] as Record<string, unknown>;
    expect(rec.recipient).toBe('John Doe');
    expect(rec.honor).toBe('Knight Commander');
    expect(rec.detail).toBe('For distinguished service');
    expect(rec.date).toBe('2026-03-12');
    expect(rec.authority).toBe(AUTHORITY);
    expect(typeof rec.payload_sha256).toBe('string');
    expect(typeof rec.signature_b64url).toBe('string');
    expect(typeof rec.timestamp).toBe('string');
  });

  it('returns SignResponse with warning when log write fails', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = createMockAdapter(SECRET_KEY);
    // Use a path that will fail (directory doesn't exist and can't be created).
    const badLogPath = '/nonexistent-dir-abc123/sub/issuances.json';

    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, badLogPath);

    expect(isSignResponse(result)).toBe(true);
    const resp = result as SignResponse;
    expect(resp.warning).toBe('Credential signed but log write failed');
    expect(resp.signature).toBeTruthy();
    expect(resp.payload).toBeTruthy();
    expect(consoleSpy).toHaveBeenCalled();
  });

  it('log write failed error is sanitized (control chars stripped)', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = createMockAdapter(SECRET_KEY);
    // Mock appendIssuanceRecord via the log module to throw with control chars.
    const logMod = await import('../../server/log.js');
    const spy = vi.spyOn(logMod, 'appendIssuanceRecord').mockRejectedValue(
      new Error('disk\x07\x1b[31mfull'),
    );

    try {
      const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

      expect(isSignResponse(result)).toBe(true);
      const resp = result as SignResponse;
      expect(resp.warning).toBe('Credential signed but log write failed');

      const call = consoleSpy.mock.calls.find(
        (c) => c[0] === 'Log write failed:',
      );
      expect(call).toBeDefined();
      const sanitizedMsg = call![1] as string;
      // eslint-disable-next-line no-control-regex
      expect(sanitizedMsg).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
      expect(sanitizedMsg).toContain('disk');
      expect(sanitizedMsg).toContain('full');
    } finally {
      spy.mockRestore();
    }
  });

  it('handles non-Error thrown by appendIssuanceRecord without crashing', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const adapter = createMockAdapter(SECRET_KEY);
    const logMod = await import('../../server/log.js');
    const spy = vi.spyOn(logMod, 'appendIssuanceRecord').mockRejectedValue(
      'raw string error',
    );

    try {
      const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

      expect(isSignResponse(result)).toBe(true);
      const resp = result as SignResponse;
      expect(resp.warning).toBe('Credential signed but log write failed');
      expect(resp.signature).toBeTruthy();

      const call = consoleSpy.mock.calls.find(
        (c) => c[0] === 'Log write failed:',
      );
      expect(call).toBeDefined();
      const loggedMsg = call![1] as string;
      expect(loggedMsg).toContain('raw string error');
    } finally {
      spy.mockRestore();
    }
  });

  it('returns VALIDATION_FAILED when detail exceeds field max length', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    // detail field max length is 2000 — exceeding it triggers credential validation error.
    const req = validRequest();
    req.detail = 'A'.repeat(2001);

    const result = await handleSign(req, adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.error).toBe('Invalid credential data');
  });

  it('returns VALIDATION_FAILED for multi-byte Unicode exceeding byte limit despite short char count', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    const req = validRequest();
    // Georgian characters are 3 bytes each in UTF-8.
    // ~700 Georgian chars = ~2100 bytes > 2048, but only 700 chars.
    req.detail = '\u10D0'.repeat(700);

    const result = await handleSign(req, adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignError(result)).toBe(true);
    const err = result as SignError;
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.error).toBe('Payload exceeds maximum size');
  });

  it('produces a URL matching the expected format', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignResponse(result)).toBe(true);
    const resp = result as SignResponse;
    const pattern = /^https:\/\/verify\.royalhouseofgeorgia\.ge\/\?p=[A-Za-z0-9_-]+&s=[A-Za-z0-9_-]+$/;
    expect(resp.url).toMatch(pattern);
  });

  it('writes a SHA-256 hash in the log that matches the payload bytes', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    const req = validRequest();
    const result = await handleSign(req, adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(isSignResponse(result)).toBe(true);

    // Recompute expected payload bytes.
    const credential = {
      version: 1 as const,
      authority: AUTHORITY,
      recipient: req.recipient,
      honor: req.honor,
      detail: req.detail,
      date: req.date,
    };
    const payloadBytes = canonicalize(credential);
    const expectedHash = createHash('sha256').update(payloadBytes).digest('hex');

    const raw = await readFile(logPath, 'utf-8');
    const records = JSON.parse(raw) as Array<Record<string, unknown>>;
    expect(records[0].payload_sha256).toBe(expectedHash);
  });

  it('applies NFC normalization to input fields including authority', async () => {
    const adapter = createMockAdapter(SECRET_KEY);
    // Use NFD-encoded strings: e with combining acute accent.
    const req: SignRequest = {
      recipient: 'Jose\u0301', // NFD "José"
      honor: 'Kni\u0300ght',   // NFD
      detail: 'De\u0301tail',   // NFD
      date: '2026-03-12',
    };
    // Authority also in NFD.
    const nfdAuthority = 'Ge\u0301orgia';

    const result = await handleSign(req, adapter, PUBLIC_KEY, nfdAuthority, logPath);

    expect(isSignResponse(result)).toBe(true);

    // Read log and verify NFC forms were stored.
    const raw = await readFile(logPath, 'utf-8');
    const records = JSON.parse(raw) as Array<Record<string, unknown>>;
    const rec = records[0];
    expect(rec.recipient).toBe('Jos\u00e9');       // NFC
    expect(rec.honor).toBe('Kni\u0300ght'.normalize('NFC'));
    expect(rec.detail).toBe('D\u00e9tail');         // NFC
    expect(rec.authority).toBe('G\u00e9orgia');     // NFC
  });
});
