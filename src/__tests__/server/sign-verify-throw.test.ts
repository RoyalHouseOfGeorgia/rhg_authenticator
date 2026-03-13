import { mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import type { SignError } from '../../server/sign.js';
import type { SigningAdapter } from '../../server/types.js';

// Mock the crypto module so we can make verify() throw on demand.
const verifyMock = vi.fn<(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array) => boolean>();
vi.mock('../../crypto.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../crypto.js')>();
  return {
    ...actual,
    verify: (...args: [Uint8Array, Uint8Array, Uint8Array]) => verifyMock(...args),
  };
});

// Import handleSign AFTER vi.mock so it picks up the mocked verify.
const { handleSign } = await import('../../server/sign.js');

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

function validRequest() {
  return {
    recipient: 'John Doe',
    honor: 'Knight Commander',
    detail: 'For distinguished service',
    date: '2026-03-12',
  };
}

const AUTHORITY = 'Royal House of Georgia';

let testDir: string;
let logPath: string;

describe('handleSign post-sign verification throw', () => {
  beforeEach(async () => {
    testDir = join(tmpdir(), `sign-vthrow-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(testDir, { recursive: true });
    logPath = join(testDir, 'issuances.json');
    verifyMock.mockReset();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(testDir, { recursive: true, force: true });
  });

  it('logs sanitized error and returns SIGNING_FAILED when verify throws an Error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    verifyMock.mockImplementation(() => {
      throw new Error('bad point on curve');
    });

    const adapter = createMockAdapter(SECRET_KEY);
    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(result).toEqual({
      error: 'Signing operation failed',
      code: 'SIGNING_FAILED',
    });
    expect(consoleSpy).toHaveBeenCalledWith(
      'Post-sign verification threw:',
      'bad point on curve',
    );
  });

  it('returns SIGNING_FAILED without logging details when verify throws a non-Error', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    verifyMock.mockImplementation(() => {
      throw 'string error'; // eslint-disable-line no-throw-literal
    });

    const adapter = createMockAdapter(SECRET_KEY);
    const result = await handleSign(validRequest(), adapter, PUBLIC_KEY, AUTHORITY, logPath);

    expect(result).toEqual({
      error: 'Signing operation failed',
      code: 'SIGNING_FAILED',
    });
    // console.error should NOT have been called since thrown value is not an Error instance.
    expect(consoleSpy).not.toHaveBeenCalled();
  });
});
