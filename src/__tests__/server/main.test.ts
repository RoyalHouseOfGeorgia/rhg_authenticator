import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import type { SigningAdapter } from '../../server/types.js';
import type { Registry } from '../../registry.js';
import type { RegistryFetchResult } from '../../server/types.js';

// Deterministic test key pair.
const SECRET_KEY = new Uint8Array(32);
SECRET_KEY[0] = 0x01;
SECRET_KEY[31] = 0xff;
const PUBLIC_KEY = ed25519.getPublicKey(SECRET_KEY);
const PUBLIC_KEY_B64 = Buffer.from(PUBLIC_KEY).toString('base64');

// A second, different key for mismatch tests.
const OTHER_SECRET = new Uint8Array(32);
OTHER_SECRET[0] = 0x02;
OTHER_SECRET[31] = 0xfe;
const OTHER_PUBLIC_KEY_B64 = Buffer.from(ed25519.getPublicKey(OTHER_SECRET)).toString('base64');

function createMockAdapter(): SigningAdapter {
  return {
    exportPublicKey: async () => PUBLIC_KEY,
    signBytes: async (data: Uint8Array) => ed25519.sign(data, SECRET_KEY),
  };
}

function makeRegistry(overrides?: Partial<Registry['keys'][0]>[]): Registry {
  if (overrides) {
    return {
      keys: overrides.map((o) => ({
        authority: 'Test Authority',
        from: '2020-01-01',
        to: null,
        algorithm: 'Ed25519' as const,
        public_key: PUBLIC_KEY_B64,
        note: 'test key',
        ...o,
      })),
    };
  }
  return {
    keys: [
      {
        authority: 'Test Authority',
        from: '2020-01-01',
        to: null,
        algorithm: 'Ed25519' as const,
        public_key: PUBLIC_KEY_B64,
        note: 'test key',
      },
    ],
  };
}

vi.mock('../../server/registry-fetch.js', () => ({
  fetchAndValidateRegistry: vi.fn(),
}));

// Lazy import so the mock is in place before the module loads.
const { fetchAndValidateRegistry } = await import('../../server/registry-fetch.js');
const mockFetch = vi.mocked(fetchAndValidateRegistry);

// Import startServer after the mock is set up.
const { startServer } = await import('../../server/main.js');

let closeFn: (() => void) | null = null;

afterEach(() => {
  if (closeFn) {
    closeFn();
    closeFn = null;
  }
  vi.restoreAllMocks();
});

function setMockRegistry(registry: Registry, source: 'remote' | 'local' = 'remote', warning?: string): void {
  const result: RegistryFetchResult = { registry, source };
  if (warning) result.warning = warning;
  mockFetch.mockResolvedValue(result);
}

// Use a dynamic port to avoid conflicts.
let nextPort = 30_000;
function getPort(): number {
  return nextPort++;
}

describe('startServer', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('starts with a matching key and returns server, port, and token', async () => {
    const port = getPort();
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    expect(result.server).toBeDefined();
    expect(result.port).toBe(port);
    expect(result.token).toMatch(/^[0-9a-f]{64}$/);
    expect(result.server.listening).toBe(true);
  });

  it('throws when no registry key matches the adapter key', async () => {
    const port = getPort();
    setMockRegistry(makeRegistry([{ public_key: OTHER_PUBLIC_KEY_B64 }]));

    await expect(
      startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
      }),
    ).rejects.toThrow('No active registry entry matches the YubiKey public key');
  });

  it('throws when the matching key is revoked (to in the past)', async () => {
    const port = getPort();
    setMockRegistry(makeRegistry([{ to: '2020-01-01' }]));

    await expect(
      startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
      }),
    ).rejects.toThrow('No active registry entry matches the YubiKey public key');
  });

  it('throws when the matching key from-date is in the future', async () => {
    const port = getPort();
    setMockRegistry(makeRegistry([{ from: '2025-01-01' }]));

    await expect(
      startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2020-01-01T00:00:00Z'),
      }),
    ).rejects.toThrow('No active registry entry matches the YubiKey public key');
  });

  it('selects the correct entry in a multi-entry registry', async () => {
    const port = getPort();
    const registry = makeRegistry([
      { public_key: OTHER_PUBLIC_KEY_B64, authority: 'Wrong Authority' },
      { public_key: PUBLIC_KEY_B64, authority: 'Correct Authority' },
    ]);
    setMockRegistry(registry);

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    // Verify the banner includes the correct authority.
    const errorCalls = vi.mocked(console.error).mock.calls;
    const banner = errorCalls.find((c) => typeof c[0] === 'string' && c[0].includes('matched:'));
    expect(banner).toBeDefined();
    expect(banner![0]).toContain('matched: Correct Authority');
  });

  it('refreshes registry on interval', async () => {
    vi.useFakeTimers();
    const port = getPort();
    const initialRegistry = makeRegistry();
    setMockRegistry(initialRegistry);

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    // Reset the mock call count after startup.
    mockFetch.mockClear();
    const updatedRegistry = makeRegistry([{ authority: 'Updated Authority' }]);
    setMockRegistry(updatedRegistry);

    // Advance timer by 60s to trigger refresh.
    await vi.advanceTimersByTimeAsync(60_000);

    expect(mockFetch).toHaveBeenCalledTimes(1);

    vi.useRealTimers();
  });

  it('registry refresh error log is sanitized (control chars stripped)', async () => {
    vi.useFakeTimers();
    const port = getPort();
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    // Reset mock after startup, make it reject with control chars.
    mockFetch.mockReset();
    mockFetch.mockRejectedValue(new Error('net\x07\x1b[31mfail'));

    const consoleSpy = vi.mocked(console.error);
    consoleSpy.mockClear();

    await vi.advanceTimersByTimeAsync(60_000);

    const call = consoleSpy.mock.calls.find(
      (c) => typeof c[0] === 'string' && c[0].startsWith('Registry refresh failed:'),
    );
    expect(call).toBeDefined();
    const msg = call![0] as string;
    // eslint-disable-next-line no-control-regex
    expect(msg).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
    expect(msg).toContain('net');
    expect(msg).toContain('fail');

    vi.useRealTimers();
  });

  it('registry refresh logs warning when key is no longer active', async () => {
    vi.useFakeTimers();
    const port = getPort();
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    // After startup, mock refresh to return a registry where the key is revoked (to date in the past).
    mockFetch.mockReset();
    const revokedRegistry = makeRegistry([{ to: '2024-01-01' }]);
    setMockRegistry(revokedRegistry);

    const consoleSpy = vi.mocked(console.error);
    consoleSpy.mockClear();

    await vi.advanceTimersByTimeAsync(60_000);

    const call = consoleSpy.mock.calls.find(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('no longer active'),
    );
    expect(call).toBeDefined();
    expect(call![0]).toContain('WARNING: YubiKey public key no longer active');

    vi.useRealTimers();
  });

  it('registry refresh warning log is sanitized (control chars stripped)', async () => {
    vi.useFakeTimers();
    const port = getPort();
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    // Reset mock after startup, make it resolve with a warning containing control chars.
    mockFetch.mockReset();
    const warningResult: RegistryFetchResult = {
      registry: makeRegistry(),
      source: 'remote',
      warning: 'stale\x07\x1b[31mdata',
    };
    mockFetch.mockResolvedValue(warningResult);

    const consoleSpy = vi.mocked(console.error);
    consoleSpy.mockClear();

    await vi.advanceTimersByTimeAsync(60_000);

    const call = consoleSpy.mock.calls.find(
      (c) => typeof c[0] === 'string' && c[0].startsWith('Registry refresh warning:'),
    );
    expect(call).toBeDefined();
    const msg = call![0] as string;
    // eslint-disable-next-line no-control-regex
    expect(msg).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
    expect(msg).toContain('stale');
    expect(msg).toContain('data');

    vi.useRealTimers();
  });

  it('close() clears interval and stops server', async () => {
    const port = getPort();
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });

    expect(result.server.listening).toBe(true);
    result.close();

    // Server begins closing (may not be immediate, wait for it).
    await new Promise<void>((resolve) => {
      result.server.on('close', resolve);
      // If already closed, resolve immediately.
      if (!result.server.listening) resolve();
    });
    expect(result.server.listening).toBe(false);
  });

  describe('token in startup banner', () => {
    it('prints the full bearer token in the banner', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());

      const result = await startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
      });
      closeFn = result.close;

      expect(result.token).toMatch(/^[0-9a-f]{64}$/);

      const errorCalls = vi.mocked(console.error).mock.calls;
      const bannerCall = errorCalls.find(
        (c) => typeof c[0] === 'string' && c[0].includes('Bearer token:'),
      );
      expect(bannerCall).toBeDefined();
      expect(bannerCall![0]).toContain(`Bearer token: ${result.token}`);
    });

    it('prints SHA-256 fingerprint on a separate line matching the token', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());

      const result = await startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
      });
      closeFn = result.close;

      const { createHash } = await import('node:crypto');
      const expectedFingerprint = createHash('sha256').update(result.token).digest('hex').slice(0, 16);

      const errorCalls = vi.mocked(console.error).mock.calls;
      const bannerCall = errorCalls.find(
        (c) => typeof c[0] === 'string' && c[0].includes('Token fingerprint:'),
      );
      expect(bannerCall).toBeDefined();
      expect(bannerCall![0]).toContain(`Token fingerprint: ${expectedFingerprint}`);
    });

    it('banner contains both bearer token and fingerprint lines', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());

      const result = await startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
      });
      closeFn = result.close;

      const errorCalls = vi.mocked(console.error).mock.calls;
      const bannerCall = errorCalls.find(
        (c) => typeof c[0] === 'string' && c[0].includes('Bearer token:'),
      );
      expect(bannerCall).toBeDefined();
      expect(bannerCall![0]).toContain('Token fingerprint:');
    });
  });

  it('returns the actual port when started with port 0 (ephemeral)', async () => {
    setMockRegistry(makeRegistry());

    const result = await startServer({
      config: { port: 0 },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    expect(result.port).toBeGreaterThan(0);
    expect(result.server.listening).toBe(true);
    // Verify the banner uses the actual port, not 0.
    const errorCalls = vi.mocked(console.error).mock.calls;
    const bannerCall = errorCalls.find(
      (c) => typeof c[0] === 'string' && c[0].includes('RHG Signing Server running on'),
    );
    expect(bannerCall).toBeDefined();
    expect(bannerCall![0]).not.toContain(':0');
    expect(bannerCall![0]).toContain(`:${result.port}`);
  });

  describe('tokenFilePath option', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rhg-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('writes token to file with 0o600 permissions and omits raw token from banner', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());
      const tokenFilePath = path.join(tmpDir, 'token');

      const result = await startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
        tokenFilePath,
      });
      closeFn = result.close;

      // Verify file content
      const fileContent = fs.readFileSync(tokenFilePath, 'utf-8');
      expect(fileContent).toBe(result.token + '\n');

      // Verify file permissions (owner read+write only)
      const stat = fs.statSync(tokenFilePath);
      expect(stat.mode & 0o777).toBe(0o600);

      // Verify banner omits raw token but includes "written to" message
      const errorCalls = vi.mocked(console.error).mock.calls;
      const bannerCall = errorCalls.find(
        (c) => typeof c[0] === 'string' && c[0].includes('RHG Signing Server'),
      );
      expect(bannerCall).toBeDefined();
      expect(bannerCall![0]).toContain(`Bearer token written to: ${tokenFilePath}`);
      expect(bannerCall![0]).not.toContain(`Bearer token: ${result.token}`);
    });

    it('still includes fingerprint in banner when tokenFilePath is set', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());
      const tokenFilePath = path.join(tmpDir, 'token');

      const result = await startServer({
        config: { port },
        adapter: createMockAdapter(),
        now: new Date('2025-06-01T00:00:00Z'),
        tokenFilePath,
      });
      closeFn = result.close;

      const { createHash } = await import('node:crypto');
      const expectedFingerprint = createHash('sha256').update(result.token).digest('hex').slice(0, 16);

      const errorCalls = vi.mocked(console.error).mock.calls;
      const bannerCall = errorCalls.find(
        (c) => typeof c[0] === 'string' && c[0].includes('Token fingerprint:'),
      );
      expect(bannerCall).toBeDefined();
      expect(bannerCall![0]).toContain(`Token fingerprint: ${expectedFingerprint}`);
    });

    it('fails fast with clear error when parent directory does not exist', async () => {
      const port = getPort();
      setMockRegistry(makeRegistry());
      const tokenFilePath = path.join(tmpDir, 'nonexistent', 'subdir', 'token');

      await expect(
        startServer({
          config: { port },
          adapter: createMockAdapter(),
          now: new Date('2025-06-01T00:00:00Z'),
          tokenFilePath,
        }),
      ).rejects.toThrow(/Cannot write token file: parent directory does not exist or is not writable/);
    });
  });

  it('NFC-normalizes the authority from the matched entry', async () => {
    const port = getPort();
    // NFD form of e-acute: e + combining acute accent
    const nfdAuthority = 'Caf\u0065\u0301';
    const nfcAuthority = nfdAuthority.normalize('NFC');
    setMockRegistry(makeRegistry([{ authority: nfdAuthority }]));

    const result = await startServer({
      config: { port },
      adapter: createMockAdapter(),
      now: new Date('2025-06-01T00:00:00Z'),
    });
    closeFn = result.close;

    const errorCalls = vi.mocked(console.error).mock.calls;
    const banner = errorCalls.find((c) => typeof c[0] === 'string' && c[0].includes('matched:'));
    expect(banner).toBeDefined();
    expect(banner![0]).toContain(`matched: ${nfcAuthority}`);
    // Confirm it is NFC (single codepoint for e-acute).
    expect(banner![0]).toContain('Caf\u00e9');
  });
});
