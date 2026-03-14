import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import dns from 'node:dns';
import { fetchAndValidateRegistry, MAX_REGISTRY_BYTES, validateResolvedIp } from '../../server/registry-fetch.js';

const VALID_REGISTRY = {
  keys: [
    {
      authority: 'Test Authority',
      from: '2020-01-01',
      to: null,
      algorithm: 'Ed25519' as const,
      public_key: '/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=',
      note: 'test key',
    },
  ],
};

const REMOTE_URL = 'https://example.com/registry.json';

let tmpDir: string | undefined;

async function makeTmpDir(): Promise<string> {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'reg-fetch-test-'));
  return tmpDir;
}

async function writeLocalRegistry(
  dir: string,
  content: unknown,
): Promise<string> {
  const filePath = path.join(dir, 'registry.json');
  await fs.writeFile(filePath, JSON.stringify(content), 'utf-8');
  return filePath;
}

// Default: DNS resolves to a public IP so existing tests pass the SSRF DNS check.
beforeEach(() => {
  vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '93.184.216.34', family: 4 });
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (tmpDir) {
    await fs.rm(tmpDir, { recursive: true, force: true });
    tmpDir = undefined;
  }
});

function mockFetch(
  body: unknown,
  status = 200,
): typeof globalThis.fetch {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
}

function mockFetchText(
  text: string,
  status = 200,
): typeof globalThis.fetch {
  return async () =>
    new Response(text, {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
}

describe('URL validation (SSRF prevention)', () => {
  it('rejects HTTP URL', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('http://example.com/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/Registry URL must use HTTPS/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects localhost', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://localhost/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/must not target localhost/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects 127.0.0.1', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://127.0.0.1/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/must not target localhost/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects [::1]', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://[::1]/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/must not target localhost/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects 0.0.0.0', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://0.0.0.0/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/must not target localhost/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects [::]', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://[::]/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/must not target localhost/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects private IP 10.x.x.x (via DNS resolution)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '10.0.1.5', family: 4 });
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://10.0.1.5/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/resolved to private IP/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects private IP 172.16.x.x (via DNS resolution)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '172.16.0.1', family: 4 });
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://172.16.0.1/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/resolved to private IP/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects private IP 192.168.x.x (via DNS resolution)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '192.168.1.1', family: 4 });
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://192.168.1.1/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/resolved to private IP/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects link-local 169.254.x.x (via DNS resolution)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '169.254.169.254', family: 4 });
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('https://169.254.169.254/registry.json', '/nonexistent', fetchFn),
    ).rejects.toThrow(/resolved to private IP/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('accepts valid HTTPS URL', async () => {
    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      '/nonexistent',
      mockFetch(VALID_REGISTRY),
    );
    expect(result.source).toBe('remote');
  });

  it('error message is sanitized (URL with control chars)', async () => {
    const fetchFn = vi.fn();
    try {
      await fetchAndValidateRegistry('http://example\x1b[31m.com/reg', '/nonexistent', fetchFn);
    } catch (e) {
      const msg = (e as Error).message;
      // eslint-disable-next-line no-control-regex
      expect(msg).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
    }
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fetchAndValidateRegistry throws before fetching when URL is invalid', async () => {
    const fetchFn = vi.fn();
    await expect(
      fetchAndValidateRegistry('not-a-url', '/nonexistent', fetchFn),
    ).rejects.toThrow(/Invalid registry URL/);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe('fetchAndValidateRegistry', () => {
  it('returns source "remote" on successful fetch', async () => {
    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      '/nonexistent',
      mockFetch(VALID_REGISTRY),
    );
    expect(result.source).toBe('remote');
    expect(result.registry.keys).toHaveLength(1);
    expect(result.registry.keys[0].authority).toBe('Test Authority');
    expect(result.warning).toBeUndefined();
  });

  it('falls back to local on network error with warning', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };

    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      localPath,
      failFetch,
    );
    expect(result.source).toBe('local');
    expect(result.warning).toBe('Registry fetch failed');
    expect(result.registry.keys).toHaveLength(1);
  });

  it('falls back to local on HTTP 500 with status in warning', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      localPath,
      mockFetch({}, 500),
    );
    expect(result.source).toBe('local');
    expect(result.warning).toBe(
      'Registry returned HTTP 500, using local fallback',
    );
  });

  it('falls back to local on HTTP 404 with status in warning', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      localPath,
      mockFetch({}, 404),
    );
    expect(result.source).toBe('local');
    expect(result.warning).toBe(
      'Registry returned HTTP 404, using local fallback',
    );
  });

  it('throws on remote invalid JSON without fallback', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    await expect(
      fetchAndValidateRegistry(
        REMOTE_URL,
        localPath,
        mockFetchText('not json', 200),
      ),
    ).rejects.toThrow(/Registry JSON parse error/);
  });

  it('throws on remote valid JSON but invalid schema without fallback', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    await expect(
      fetchAndValidateRegistry(
        REMOTE_URL,
        localPath,
        mockFetch({ bad: 'schema' }),
      ),
    ).rejects.toThrow(/missing required field: keys/);
  });

  it('parse error message is distinct from schema error message', async () => {
    const parseErr = fetchAndValidateRegistry(
      REMOTE_URL,
      '/nonexistent',
      mockFetchText('{{bad', 200),
    );
    const schemaErr = fetchAndValidateRegistry(
      REMOTE_URL,
      '/nonexistent',
      mockFetch({ bad: 'data' }),
    );

    const [parseResult, schemaResult] = await Promise.allSettled([
      parseErr,
      schemaErr,
    ]);

    expect(parseResult.status).toBe('rejected');
    expect(schemaResult.status).toBe('rejected');

    const parseMsg = (parseResult as PromiseRejectedResult).reason.message;
    const schemaMsg = (schemaResult as PromiseRejectedResult).reason.message;

    expect(parseMsg).toContain('JSON parse error');
    expect(schemaMsg).not.toContain('JSON parse error');
  });

  it('throws when both remote and local are unavailable', async () => {
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };

    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent/path', failFetch),
    ).rejects.toThrow(/Registry unavailable.*remote failed.*local file/);
  });

  it('falls back to local with timeout warning on DOMException TimeoutError', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    const timeoutFetch: typeof globalThis.fetch = async () => {
      const err = new DOMException('The operation was aborted', 'TimeoutError');
      throw err;
    };

    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      localPath,
      timeoutFetch,
    );
    expect(result.source).toBe('local');
    expect(result.warning).toBe('Registry fetch timed out');
  });

  it('falls back to local with timeout warning on TypeError wrapping TimeoutError', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, VALID_REGISTRY);

    const timeoutFetch: typeof globalThis.fetch = async () => {
      const cause = { name: 'TimeoutError' };
      throw new TypeError('fetch failed', { cause });
    };

    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      localPath,
      timeoutFetch,
    );
    expect(result.source).toBe('local');
    expect(result.warning).toBe('Registry fetch timed out');
  });

  it('throws when local file is missing after remote failure', async () => {
    const dir = await makeTmpDir();
    const missingPath = path.join(dir, 'does-not-exist.json');

    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };

    await expect(
      fetchAndValidateRegistry(REMOTE_URL, missingPath, failFetch),
    ).rejects.toThrow(/Registry unavailable.*local file unreadable/);
  });

  it('throws when local file has invalid schema after remote failure', async () => {
    const dir = await makeTmpDir();
    const localPath = await writeLocalRegistry(dir, { bad: 'schema' });

    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };

    await expect(
      fetchAndValidateRegistry(REMOTE_URL, localPath, failFetch),
    ).rejects.toThrow(/missing required field: keys/);
  });

  // --- M6: Registry response size limit ---

  it('exports MAX_REGISTRY_BYTES as 1 MB', () => {
    expect(MAX_REGISTRY_BYTES).toBe(1_048_576);
  });

  it('throws when Content-Length exceeds limit on 2xx response', async () => {
    const bigFetch: typeof globalThis.fetch = async () =>
      new Response('{}', {
        status: 200,
        headers: { 'Content-Length': '2000000' },
      });
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', bigFetch),
    ).rejects.toThrow(/too large/);
  });

  it('does not reject when Content-Length is below limit', async () => {
    const result = await fetchAndValidateRegistry(
      REMOTE_URL,
      '/nonexistent',
      mockFetch(VALID_REGISTRY),
    );
    expect(result.source).toBe('remote');
  });

  it('ignores non-numeric Content-Length header', async () => {
    const fetchFn: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(VALID_REGISTRY), {
        status: 200,
        headers: { 'Content-Length': 'not-a-number' },
      });
    const result = await fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', fetchFn);
    expect(result.source).toBe('remote');
  });

  it('throws when body exceeds limit without Content-Length on 2xx response', async () => {
    const bigBody = 'x'.repeat(MAX_REGISTRY_BYTES + 1);
    const bigFetch: typeof globalThis.fetch = async () =>
      new Response(bigBody, { status: 200 });
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', bigFetch),
    ).rejects.toThrow(/too large/);
  });

  it('succeeds when body is exactly at the size limit', async () => {
    const base = JSON.stringify(VALID_REGISTRY);
    const padding = ' '.repeat(MAX_REGISTRY_BYTES - base.length);
    const exactBody = base + padding;
    const fetchFn: typeof globalThis.fetch = async () =>
      new Response(exactBody, { status: 200 });
    const result = await fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', fetchFn);
    expect(result.source).toBe('remote');
    expect(result.registry.keys).toHaveLength(1);
  });

  it('throws when Content-Length is exactly at limit + 1 on 2xx response', async () => {
    const fetchFn: typeof globalThis.fetch = async () =>
      new Response('{}', {
        status: 200,
        headers: { 'Content-Length': String(MAX_REGISTRY_BYTES + 1) },
      });
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', fetchFn),
    ).rejects.toThrow(/too large/);
  });

  it('does not reject when Content-Length equals exactly the limit', async () => {
    const fetchFn: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify(VALID_REGISTRY), {
        status: 200,
        headers: { 'Content-Length': String(MAX_REGISTRY_BYTES) },
      });
    const result = await fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', fetchFn);
    expect(result.source).toBe('remote');
  });

  it('throws when arrayBuffer() rejects on 2xx response (body-read failure)', async () => {
    const brokenFetch: typeof globalThis.fetch = async () => {
      const resp = new Response('ok', { status: 200 });
      resp.arrayBuffer = async () => {
        throw new Error('network stream interrupted');
      };
      return resp;
    };
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', brokenFetch),
    ).rejects.toThrow(/could not be processed/);
  });

  it('throws when Content-Length lies small but actual body exceeds limit', async () => {
    const bigBody = 'x'.repeat(MAX_REGISTRY_BYTES + 1);
    const lyingFetch: typeof globalThis.fetch = async () =>
      new Response(bigBody, {
        status: 200,
        headers: { 'Content-Length': '100' },
      });
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', lyingFetch),
    ).rejects.toThrow(/too large/);
  });

  // --- Log injection: sanitize + truncate error details ---

  it('sanitizes and truncates control characters in error details', async () => {
    const controlChars = 'error\x1b[31m\x00message';
    const mockFetchFn: typeof globalThis.fetch = async () => {
      const resp = new Response(null, { status: 200 });
      resp.arrayBuffer = () => Promise.reject(new Error(controlChars));
      return resp;
    };
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'reg.json');
    await expect(
      fetchAndValidateRegistry(REMOTE_URL, lp, mockFetchFn),
    ).rejects.toThrow(/Registry response could not be processed/);
    try {
      await fetchAndValidateRegistry(REMOTE_URL, lp, mockFetchFn);
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toMatch(/\x1b/);
      expect(msg).not.toMatch(/\x00/);
    }
  });

  it('truncates very long error details to 200 chars', async () => {
    const longMsg = 'x'.repeat(500);
    const mockFetchFn: typeof globalThis.fetch = async () => {
      const resp = new Response(null, { status: 200 });
      resp.arrayBuffer = () => Promise.reject(new Error(longMsg));
      return resp;
    };
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'reg.json');
    try {
      await fetchAndValidateRegistry(REMOTE_URL, lp, mockFetchFn);
    } catch (e) {
      const msg = (e as Error).message;
      const detailPart = msg.replace('Registry response could not be processed: ', '');
      expect(detailPart.length).toBeLessThanOrEqual(200);
    }
  });

  it('sanitizes control characters in JSON parse error messages', async () => {
    const evilJson = '{ invalid \x1b[31m json }';
    const mockFetchFn: typeof globalThis.fetch = async () =>
      new Response(evilJson, { status: 200 });
    try {
      await fetchAndValidateRegistry(REMOTE_URL, '/nonexistent', mockFetchFn);
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/Registry JSON parse error/);
      expect(msg).not.toMatch(/\x1b/);
    }
  });

  it('sanitizes control characters in local fallback file-read error details', async () => {
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };
    const dir = await makeTmpDir();
    const badPath = path.join(dir, 'nonexistent', 'reg.json');
    try {
      await fetchAndValidateRegistry(REMOTE_URL, badPath, failFetch);
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/local file unreadable/);
    }
  });

  it('sanitizes control characters in local fallback JSON parse error details', async () => {
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'bad.json');
    await fs.writeFile(lp, '{ not \x1b[31m valid }', 'utf-8');
    try {
      await fetchAndValidateRegistry(REMOTE_URL, lp, failFetch);
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/local file has invalid JSON/);
      expect(msg).not.toMatch(/\x1b/);
    }
  });

  it('truncates very long local fallback error details to 200 chars', async () => {
    const failFetch: typeof globalThis.fetch = async () => {
      throw new Error('ECONNREFUSED');
    };
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'bad.json');
    await fs.writeFile(lp, '{ "key": "' + 'x'.repeat(500), 'utf-8');
    try {
      await fetchAndValidateRegistry(REMOTE_URL, lp, failFetch);
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes('local file has invalid JSON')) {
        const detailPart = msg.replace(
          'Registry unavailable: remote failed and local file has invalid JSON: ',
          '',
        );
        expect(detailPart.length).toBeLessThanOrEqual(200);
      }
    }
  });
});

describe('validateResolvedIp (DNS-based SSRF prevention)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('throws when DNS resolves to private IPv4 127.0.0.1', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '127.0.0.1', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 127.0.0.1',
    );
  });

  it('throws when DNS resolves to private IPv4 10.x', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '10.0.0.1', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 10.0.0.1',
    );
  });

  it('throws when DNS resolves to private IPv4 192.168.x', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '192.168.1.1', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 192.168.1.1',
    );
  });

  it('throws when DNS resolves to private IPv4 172.16.x', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '172.16.0.1', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 172.16.0.1',
    );
  });

  it('throws when DNS resolves to link-local 169.254.x', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '169.254.169.254', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 169.254.169.254',
    );
  });

  it('throws when DNS resolves to 0.0.0.0', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '0.0.0.0', family: 4 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: 0.0.0.0',
    );
  });

  it('throws when DNS resolves to IPv6 ::1', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '::1', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: ::1',
    );
  });

  it('throws when DNS resolves to IPv6 fd00::1 (unique local)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: 'fd00::1', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: fd00::1',
    );
  });

  it('throws when DNS resolves to IPv6 fc00::1 (unique local)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: 'fc00::1', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: fc00::1',
    );
  });

  it('throws when DNS resolves to IPv6 fe80:: (link-local)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: 'fe80::1', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: fe80::1',
    );
  });

  it('throws when DNS resolves to IPv6 :: (unspecified)', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '::', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: ::',
    );
  });

  it('throws when DNS resolves to IPv4-mapped IPv6 ::ffff:127.0.0.1', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '::ffff:127.0.0.1', family: 6 });
    await expect(validateResolvedIp('evil.example.com')).rejects.toThrow(
      'Registry hostname resolved to private IP: ::ffff:127.0.0.1',
    );
  });

  it('does not throw when DNS resolves to public IPv4', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '93.184.216.34', family: 4 });
    await expect(validateResolvedIp('example.com')).resolves.toBeUndefined();
  });

  it('does not throw when DNS resolves to public IPv6', async () => {
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue({ address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 });
    await expect(validateResolvedIp('example.com')).resolves.toBeUndefined();
  });
});
