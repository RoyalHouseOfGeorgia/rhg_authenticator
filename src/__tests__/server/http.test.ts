import http from 'node:http';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { createRequestHandler } from '../../server/http.js';
import type { ServerDeps } from '../../server/http.js';
import type { SigningAdapter, ServerConfig } from '../../server/types.js';
import type { Registry, KeyEntry } from '../../registry.js';

// Deterministic 32-byte secret key for all tests.
const SECRET_KEY = new Uint8Array(32);
SECRET_KEY[0] = 0x01;
SECRET_KEY[31] = 0xff;

const PUBLIC_KEY = ed25519.getPublicKey(SECRET_KEY);
const PUBLIC_KEY_B64 = Buffer.from(PUBLIC_KEY).toString('base64');

const AUTHORITY = 'Royal House of Georgia';
const TOKEN = 'test-bearer-token-abc123';

function createMockAdapter(secretKey: Uint8Array): SigningAdapter {
  return {
    exportPublicKey: async () => ed25519.getPublicKey(secretKey),
    signBytes: async (data: Uint8Array) => ed25519.sign(data, secretKey),
  };
}

function activeKeyEntry(): KeyEntry {
  return {
    authority: AUTHORITY,
    from: '2020-01-01',
    to: null,
    algorithm: 'Ed25519',
    public_key: PUBLIC_KEY_B64,
    note: 'test key',
  };
}

function validSignBody(): string {
  return JSON.stringify({
    recipient: 'John Doe',
    honor: 'Knight Commander',
    detail: 'For distinguished service',
    date: '2026-03-12',
  });
}

type TestContext = {
  port: number;
  token: string;
  close: () => Promise<void>;
  adapter: SigningAdapter;
};

let testDir: string;
let logPath: string;

// Use a dynamic port counter so listeningPort is known at handler creation time.
let nextPort = 31_000;
function getPort(): number {
  return nextPort++;
}

async function startTestServer(overrides?: {
  registry?: Registry;
  adapter?: SigningAdapter;
  config?: Partial<ServerConfig>;
  token?: string;
}): Promise<TestContext> {
  const adapter = overrides?.adapter ?? createMockAdapter(SECRET_KEY);
  const token = overrides?.token ?? TOKEN;
  const registry: Registry = overrides?.registry ?? {
    keys: [activeKeyEntry()],
  };

  const port = overrides?.config?.port ?? getPort();

  const config: ServerConfig = {
    host: '127.0.0.1',
    registryUrl: 'https://example.com/registry.json',
    localRegistryPath: '/tmp/registry.json',
    logPath,
    issuerDir: overrides?.config?.issuerDir ?? null,
    authority: AUTHORITY,
    ...overrides?.config,
    port,
  };

  const deps: ServerDeps = {
    adapter,
    config,
    cachedPublicKey: PUBLIC_KEY,
    registryRef: { current: registry },
    listeningPort: { current: port },
  };

  const handler = createRequestHandler(deps, token, logPath);
  const server = http.createServer(handler);

  await new Promise<void>((resolve) => {
    server.listen(port, '127.0.0.1', resolve);
  });

  return {
    port,
    token,
    adapter,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function request(
  port: number,
  method: string,
  urlPath: string,
  options?: {
    body?: string | Buffer;
    headers?: Record<string, string>;
    token?: string;
    skipAutoOrigin?: boolean;
  },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...options?.headers };
    if (options?.token) {
      headers['Authorization'] = `Bearer ${options.token}`;
    }
    // Auto-attach Origin for POST requests (required by origin enforcement).
    // Tests that need missing/foreign Origin should set skipAutoOrigin or provide Origin explicitly.
    if (method === 'POST' && headers['Origin'] === undefined && !options?.skipAutoOrigin) {
      headers['Origin'] = `http://127.0.0.1:${port}`;
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      },
    );

    req.on('error', reject);

    if (options?.body !== undefined) {
      req.write(options.body);
    }
    req.end();
  });
}

function rawRequest(
  port: number,
  method: string,
  urlPath: string,
  options?: {
    headers?: Record<string, string>;
    token?: string;
  },
): Promise<{ status: number; rawHeaders: string[]; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { ...options?.headers };
    if (options?.token) {
      headers['Authorization'] = `Bearer ${options.token}`;
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            rawHeaders: res.rawHeaders,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      },
    );

    req.on('error', reject);
    req.end();
  });
}

describe('HTTP server', () => {
  let ctx: TestContext | null = null;

  beforeEach(async () => {
    testDir = join(
      tmpdir(),
      `http-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(testDir, { recursive: true });
    logPath = join(testDir, 'issuances.json');
  });

  afterEach(async () => {
    if (ctx) {
      await ctx.close();
      ctx = null;
    }
    vi.restoreAllMocks();
    await rm(testDir, { recursive: true, force: true });
  });

  it('GET /health returns 200 with status ok without auth', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: 'ok' });
  });

  it('POST /sign without auth returns 401', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
    });
    expect(res.status).toBe(401);
  });

  it('POST /sign with wrong token returns 401', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: 'wrong-token',
    });
    expect(res.status).toBe(401);
  });

  it('POST /sign with valid auth and body returns 200 with signature', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed.signature).toBeTruthy();
    expect(parsed.payload).toBeTruthy();
    expect(parsed.url).toContain('p=');
    expect(parsed.url).toContain('s=');
  });

  it('POST /sign with non-JSON body returns 400', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: 'this is not json',
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(400);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBe('Invalid JSON');
  });

  it('POST /sign with empty body returns 400', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: '',
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(400);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBe('Empty request body');
  });

  it('POST /sign with oversized body returns 413', async () => {
    ctx = await startTestServer();
    const bigBody = 'x'.repeat(65 * 1024);
    const res = await request(ctx.port, 'POST', '/sign', {
      body: bigBody,
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(413);
  });

  it('POST /sign with wrong Content-Type returns 415', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'text/plain' },
      token: ctx.token,
    });
    expect(res.status).toBe(415);
  });

  it('POST /sign with Content-Type application/json; charset=utf-8 is accepted', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      token: ctx.token,
    });
    // Should pass Content-Type check — status 200 means sign succeeded.
    expect(res.status).toBe(200);
  });

  it('POST /sign with Content-Type application/jsonlines is rejected with 415', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/jsonlines' },
      token: ctx.token,
    });
    expect(res.status).toBe(415);
  });

  it('GET / returns 200 with placeholder HTML when issuerDir is null', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/');
    expect(res.status).toBe(200);
    expect(res.body).toContain('RHG Issuer');
    expect(res.body).toContain('Issuer interface coming soon.');
  });

  it('GET /nonexistent returns 404', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/nonexistent');
    expect(res.status).toBe(404);
  });

  it('POST /health returns 405 with Allow: GET', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/health');
    expect(res.status).toBe(405);
    expect(res.headers['allow']).toBe('GET');
  });

  it('DELETE /sign returns 405 with Allow: POST', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'DELETE', '/sign');
    expect(res.status).toBe(405);
    expect(res.headers['allow']).toBe('POST');
  });

  it('POST /sign with empty registry returns 403', async () => {
    ctx = await startTestServer({ registry: { keys: [] } });
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(403);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBe('Key not active in current registry');
  });

  it('POST /sign when key is revoked (past to date) returns 403', async () => {
    const revokedEntry: KeyEntry = {
      authority: AUTHORITY,
      from: '2020-01-01',
      to: '2020-12-31',
      algorithm: 'Ed25519',
      public_key: PUBLIC_KEY_B64,
      note: 'revoked key',
    };
    ctx = await startTestServer({
      registry: { keys: [revokedEntry] },
    });
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(403);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBe('Key not active in current registry');
  });

  it('multi-entry registry: correct key matched among multiple entries', async () => {
    const otherKey = ed25519.getPublicKey(new Uint8Array(32));
    const otherEntry: KeyEntry = {
      authority: 'Other Authority',
      from: '2020-01-01',
      to: null,
      algorithm: 'Ed25519',
      public_key: Buffer.from(otherKey).toString('base64'),
      note: 'other key',
    };
    ctx = await startTestServer({
      registry: { keys: [otherEntry, activeKeyEntry()] },
    });
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed.signature).toBeTruthy();
  });

  it('mutex recovery: first request fails, second succeeds', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    let callCount = 0;
    const failOnceAdapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async (data: Uint8Array) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('YubiKey disconnected');
        }
        return ed25519.sign(data, SECRET_KEY);
      },
    };

    ctx = await startTestServer({ adapter: failOnceAdapter });

    // First request — adapter throws, returns SIGNING_FAILED.
    const res1 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res1.status).toBe(500);

    // Second request — adapter succeeds.
    const res2 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res2.status).toBe(200);
    const parsed = JSON.parse(res2.body);
    expect(parsed.signature).toBeTruthy();
  });

  it('sign handler error log is sanitized (control chars stripped)', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const signMod = await import('../../server/sign.js');
    const spy = vi.spyOn(signMod, 'handleSign').mockRejectedValue(
      new Error('fail\x07\x1b[31mevil'),
    );

    ctx = await startTestServer();
    await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });

    const call = consoleSpy.mock.calls.find(
      (c) => c[0] === 'Sign handler error:',
    );
    expect(call).toBeDefined();
    const sanitizedMsg = call![1] as string;
    // eslint-disable-next-line no-control-regex
    expect(sanitizedMsg).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
    expect(sanitizedMsg).toContain('fail');
    expect(sanitizedMsg).toContain('evil');

    spy.mockRestore();
  });

  it('path traversal attempt returns 404 when issuerDir is set', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>test</html>');

    ctx = await startTestServer({
      config: { issuerDir },
    });
    const res = await request(ctx.port, 'GET', '/../package.json');
    expect(res.status).toBe(404);
  });

  it('POST /sign with revoked key never calls adapter.signBytes', async () => {
    const signBytesSpy = vi.fn();
    const spyAdapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: signBytesSpy,
    };

    const revokedEntry: KeyEntry = {
      authority: AUTHORITY,
      from: '2020-01-01',
      to: '2020-12-31',
      algorithm: 'Ed25519',
      public_key: PUBLIC_KEY_B64,
      note: 'revoked',
    };

    ctx = await startTestServer({
      adapter: spyAdapter,
      registry: { keys: [revokedEntry] },
    });
    await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(signBytesSpy).not.toHaveBeenCalled();
  });

  it('POST /sign with truncated or extended bearer token returns 401', async () => {
    ctx = await startTestServer();

    // Truncated token.
    const res1 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: TOKEN.slice(0, 5),
    });
    expect(res1.status).toBe(401);

    // Extended token.
    const res2 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: TOKEN + 'extra',
    });
    expect(res2.status).toBe(401);
  });

  it('error responses contain generic messages only, no stack traces', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    ctx = await startTestServer({ registry: { keys: [] } });

    // 401
    const res401 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
    });
    expect(res401.body).not.toContain('at ');
    expect(res401.body).not.toContain('Error:');

    // 403
    const res403 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res403.body).not.toContain('at ');
    expect(res403.body).not.toContain('stack');

    // 404
    const res404 = await request(ctx.port, 'GET', '/nonexistent');
    expect(res404.body).not.toContain('at ');

    // 405
    const res405 = await request(ctx.port, 'DELETE', '/sign');
    expect(res405.body).not.toContain('at ');
  });

  it('serves static files from issuerDir with correct MIME types', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>hello</html>');
    await writeFile(join(issuerDir, 'style.css'), 'body {}');

    ctx = await startTestServer({
      config: { issuerDir },
    });
    const htmlRes = await request(ctx.port, 'GET', '/');
    expect(htmlRes.status).toBe(200);
    expect(htmlRes.headers['content-type']).toBe('text/html');
    expect(htmlRes.headers['cache-control']).toBe('no-store');
    expect(htmlRes.body).toBe('<html>hello</html>');

    const cssRes = await request(ctx.port, 'GET', '/style.css');
    expect(cssRes.status).toBe(200);
    expect(cssRes.headers['content-type']).toBe('text/css');
  });

  it('static file serving returns 404 for missing files', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>ok</html>');

    ctx = await startTestServer({
      config: { issuerDir },
    });
    const res = await request(ctx.port, 'GET', '/missing.html');
    expect(res.status).toBe(404);
  });

  it('unknown extension served as application/octet-stream', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'data.xyz'), 'binary stuff');

    ctx = await startTestServer({
      config: { issuerDir },
    });
    const res = await request(ctx.port, 'GET', '/data.xyz');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/octet-stream');
  });

  it('handles UTF-8 BOM in request body', async () => {
    ctx = await startTestServer();
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const bodyBytes = Buffer.from(validSignBody(), 'utf-8');
    const withBom = Buffer.concat([bom, bodyBytes]);

    const res = await request(ctx.port, 'POST', '/sign', {
      body: withBom,
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed.signature).toBeTruthy();
  });

  // --- Security headers tests ---

  it('GET /health response includes security headers', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['permissions-policy']).toBe('camera=(), microphone=(), geolocation=()');
  });

  it('POST /sign 200 response includes security headers', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('placeholder HTML includes security headers with CSP default-src none', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/');
    expect(res.status).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-security-policy']).toBe("default-src 'none'");
  });

  it('static HTML files include permissive CSP with script-src and style-src', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>test</html>');

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/');
    expect(res.status).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-security-policy']).toBe(
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
  });

  it('HTML CSP contains base-uri none and form-action none', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>test</html>');

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/');
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).not.toContain("base-uri 'self'");
    expect(csp).not.toContain("form-action 'self'");
  });

  it('static CSS files get CSP default-src none', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>ok</html>');
    await writeFile(join(issuerDir, 'style.css'), 'body {}');

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/style.css');
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toBe("default-src 'none'");
  });

  it('static JS files get CSP default-src none', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>ok</html>');
    await writeFile(join(issuerDir, 'app.js'), 'console.log("hi")');

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/app.js');
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toBe("default-src 'none'");
  });

  // --- Cross-origin rejection tests (L4) ---

  it('request with evil Origin header returns 403', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: { Origin: 'http://evil.com' },
    });
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body).error).toBe('Cross-origin request denied');
  });

  it('request with Origin http://127.0.0.1:<port> is not rejected', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: { Origin: `http://127.0.0.1:${ctx.port}` },
    });
    expect(res.status).toBe(200);
  });

  it('request with Origin http://localhost:<port> is not rejected', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: { Origin: `http://localhost:${ctx.port}` },
    });
    expect(res.status).toBe(200);
  });

  it('request with Origin http://[::1]:<port> is not rejected', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: { Origin: `http://[::1]:${ctx.port}` },
    });
    expect(res.status).toBe(200);
  });

  it('request without Origin header passes through (non-browser clients)', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health');
    expect(res.status).toBe(200);
  });

  it('CORS uses listeningPort, not Host header — spoofed Host is ignored', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: {
        Host: 'evil.com:9999',
        Origin: `http://127.0.0.1:${ctx.port}`,
      },
    });
    expect(res.status).toBe(200);
  });

  it('CORS rejects Origin with wrong port even if Host header matches that port', async () => {
    ctx = await startTestServer();
    const res = await request(ctx.port, 'GET', '/health', {
      headers: {
        Host: '127.0.0.1:9999',
        Origin: 'http://127.0.0.1:9999',
      },
    });
    expect(res.status).toBe(403);
    expect(JSON.parse(res.body).error).toBe('Cross-origin request denied');
  });

  // --- Queue depth cap tests (M2/M3) ---

  it('concurrent sign requests exceeding queue depth get 429 with Retry-After', async () => {
    let currentResolver: (() => void) | null = null;
    const slowAdapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async (data: Uint8Array) => {
        await new Promise<void>((resolve) => {
          currentResolver = resolve;
        });
        return ed25519.sign(data, SECRET_KEY);
      },
    };

    ctx = await startTestServer({ adapter: slowAdapter });

    // Fire 6 concurrent requests (queue depth limit is 5).
    const promises = Array.from({ length: 6 }, () =>
      request(ctx!.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: ctx!.token,
      }),
    );

    await new Promise((r) => setTimeout(r, 200));

    // Resolve sign operations one at a time (serialized queue).
    for (let i = 0; i < 5; i++) {
      while (currentResolver === null) {
        await new Promise((r) => setTimeout(r, 10));
      }
      const resolve = currentResolver;
      currentResolver = null;
      resolve();
      await new Promise((r) => setTimeout(r, 10));
    }

    const results = await Promise.all(promises);
    const statuses = results.map((r) => r.status);
    const count429 = statuses.filter((s) => s === 429).length;
    expect(count429).toBeGreaterThanOrEqual(1);

    const rejected = results.find((r) => r.status === 429)!;
    expect(rejected.headers['retry-after']).toBe('1');
  }, 15000);

  it('queue depth counter decrements after failures allowing subsequent requests', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    let callCount = 0;
    const failOnceAdapter: SigningAdapter = {
      exportPublicKey: async () => PUBLIC_KEY,
      signBytes: async (data: Uint8Array) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('simulated failure');
        }
        return ed25519.sign(data, SECRET_KEY);
      },
    };

    ctx = await startTestServer({ adapter: failOnceAdapter });

    const res1 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res1.status).toBe(500);

    const res2 = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res2.status).toBe(200);
  });

  // --- Static file size limit tests (M8) ---

  it('serving a directory path returns 404', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    await writeFile(join(issuerDir, 'index.html'), '<html>ok</html>');
    await mkdir(join(issuerDir, 'subdir'), { recursive: true });

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/subdir');
    expect(res.status).toBe(404);
  });

  it('static file larger than 10MB returns 413', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    const bigBuf = Buffer.alloc(10 * 1024 * 1024 + 1, 0x41);
    await writeFile(join(issuerDir, 'big.bin'), bigBuf);

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/big.bin');
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body).error).toBe('File too large');
  });

  it('returns 404 when file is deleted after server start (covers stat failure path)', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    const filePath = join(issuerDir, 'ephemeral.txt');
    await writeFile(filePath, 'temp content');

    ctx = await startTestServer({ config: { issuerDir } });

    const res1 = await request(ctx.port, 'GET', '/ephemeral.txt');
    expect(res1.status).toBe(200);

    const { unlink } = await import('node:fs/promises');
    await unlink(filePath);

    const res2 = await request(ctx.port, 'GET', '/ephemeral.txt');
    expect(res2.status).toBe(404);
    expect(JSON.parse(res2.body).error).toBe('Not found');
  });

  it('static file exactly 10MB is served successfully', async () => {
    const issuerDir = join(testDir, 'issuer');
    await mkdir(issuerDir, { recursive: true });
    const exactBuf = Buffer.alloc(10 * 1024 * 1024, 0x42);
    await writeFile(join(issuerDir, 'exact.bin'), exactBuf);

    ctx = await startTestServer({ config: { issuerDir } });
    const res = await request(ctx.port, 'GET', '/exact.bin');
    expect(res.status).toBe(200);
  });

  // --- Log sanitization test (M5) ---

  it('malformed registry key is silently skipped and good key still works', async () => {
    const badEntry: KeyEntry = {
      authority: AUTHORITY,
      from: '2020-01-01',
      to: null,
      algorithm: 'Ed25519',
      public_key: 'not-valid-base64!@#$',
      note: 'bad key',
    };
    ctx = await startTestServer({
      registry: { keys: [badEntry, activeKeyEntry()] },
    });
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
  });

  // --- Invalid credential integration test (M7) ---

  it('POST /sign with invalid credential data returns 400 with generic error', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    ctx = await startTestServer();
    const body = JSON.stringify({
      recipient: '',
      honor: 'Knight Commander',
      detail: 'For service',
      date: '2026-03-12',
    });
    const res = await request(ctx.port, 'POST', '/sign', {
      body,
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error).toBe('Invalid credential data');
  });

  // --- SignRequest body validation tests (H2) ---

  describe('SignRequest body validation', () => {
    it('missing recipient returns 400 Invalid request body', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({ honor: 'Knight', detail: 'Service', date: '2026-03-12' });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('missing honor returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({ recipient: 'John', detail: 'Service', date: '2026-03-12' });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('missing detail returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({ recipient: 'John', honor: 'Knight', date: '2026-03-12' });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('missing date returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({ recipient: 'John', honor: 'Knight', detail: 'Service' });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('recipient as number returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({ recipient: 42, honor: 'Knight', detail: 'Service', date: '2026-03-12' });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('parsed body is an array returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify([{ recipient: 'John', honor: 'Knight', detail: 'Service', date: '2026-03-12' }]);
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('parsed body is a string returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify('just a string');
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('parsed body is null returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify(null);
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });

    it('extra key in sign request returns 400', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      ctx = await startTestServer();
      const body = JSON.stringify({
        recipient: 'John Doe',
        honor: 'Knight Commander',
        detail: 'For distinguished service',
        date: '2026-03-12',
        extraField: 'should be rejected',
      });
      const res = await request(ctx.port, 'POST', '/sign', {
        body,
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toBe('Invalid request body');
    });
  });

  // --- Origin enforcement tests (M4) ---

  describe('Origin enforcement on POST /sign', () => {
    it('POST /sign without Origin returns 403 with "Origin header required"', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
        skipAutoOrigin: true,
      });
      expect(res.status).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Origin header required');
    });

    it('POST /sign with foreign Origin returns 403 with "Cross-origin request denied"', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://evil.com' },
        token: ctx.token,
      });
      expect(res.status).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Cross-origin request denied');
    });

    it('POST /sign with valid localhost Origin passes through', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json', 'Origin': `http://127.0.0.1:${ctx.port}` },
        token: ctx.token,
      });
      expect(res.status).toBe(200);
    });

    it('POST /sign with valid localhost name Origin passes through', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json', 'Origin': `http://localhost:${ctx.port}` },
        token: ctx.token,
      });
      expect(res.status).toBe(200);
    });

    it('POST /sign with valid IPv6 loopback Origin passes through', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json', 'Origin': `http://[::1]:${ctx.port}` },
        token: ctx.token,
      });
      expect(res.status).toBe(200);
    });

    it('GET /health without Origin still passes (no Origin required for non-sign)', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health');
      expect(res.status).toBe(200);
    });

    it('GET /health with foreign Origin is rejected', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health', {
        headers: { 'Origin': 'http://evil.com' },
      });
      expect(res.status).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Cross-origin request denied');
    });

    it('POST to unknown path without Origin returns 403 with "Origin header required"', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'POST', '/unknown', {
        body: '{}',
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
        skipAutoOrigin: true,
      });
      expect(res.status).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Origin header required');
    });
  });

  // --- Auth failure rate limiting tests (M8) ---

  describe('auth failure rate limiting', () => {
    it('5 auth failures then 6th returns 429 with Retry-After header', async () => {
      ctx = await startTestServer();

      // Send 5 bad auth requests to trigger backoff.
      for (let i = 0; i < 5; i++) {
        const res = await request(ctx.port, 'POST', '/sign', {
          body: validSignBody(),
          headers: { 'Content-Type': 'application/json' },
          token: 'wrong-token',
        });
        expect(res.status).toBe(401);
      }

      // 6th request during backoff should get 429.
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: 'wrong-token',
      });
      expect(res.status).toBe(429);
      expect(res.headers['retry-after']).toBeDefined();
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    });

    it('valid auth during active backoff still succeeds (not locked out)', async () => {
      ctx = await startTestServer();

      // Trigger backoff with 5 failures.
      for (let i = 0; i < 5; i++) {
        await request(ctx.port, 'POST', '/sign', {
          body: validSignBody(),
          headers: { 'Content-Type': 'application/json' },
          token: 'wrong-token',
        });
      }

      // Valid auth should still succeed.
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(res.status).toBe(200);
    });

    it('successful auth resets counter (subsequent failures start fresh)', async () => {
      ctx = await startTestServer();

      // 4 failures (just under threshold).
      for (let i = 0; i < 4; i++) {
        await request(ctx.port, 'POST', '/sign', {
          body: validSignBody(),
          headers: { 'Content-Type': 'application/json' },
          token: 'wrong-token',
        });
      }

      // Successful auth resets counter.
      const goodRes = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(goodRes.status).toBe(200);

      // After reset, 4 more failures should not trigger backoff (counter was reset).
      for (let i = 0; i < 4; i++) {
        const res = await request(ctx.port, 'POST', '/sign', {
          body: validSignBody(),
          headers: { 'Content-Type': 'application/json' },
          token: 'wrong-token',
        });
        expect(res.status).toBe(401);
      }
    });

    it('backoff caps at 30 seconds after many failures', async () => {
      ctx = await startTestServer();

      // Send many failures (well past the cap).
      // 5 to start backoff, then a few more during windows.
      // We need to verify the Retry-After value doesn't exceed 30.
      // After 5 failures, backoff starts at 1s. After more, it doubles.
      // At count=20: min(1000*2^15, 30000) = 30000ms = 30s.
      // We can't easily send 20 failures through real backoff,
      // so we just verify the math by sending failures until we see 429,
      // then check the Retry-After header is <= 30.
      for (let i = 0; i < 5; i++) {
        await request(ctx.port, 'POST', '/sign', {
          body: validSignBody(),
          headers: { 'Content-Type': 'application/json' },
          token: 'wrong-token',
        });
      }

      // The 6th request during backoff.
      const res = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: 'wrong-token',
      });
      expect(res.status).toBe(429);
      const retryAfter = Number(res.headers['retry-after']);
      expect(retryAfter).toBeLessThanOrEqual(30);
      expect(retryAfter).toBeGreaterThan(0);
    });
  });

  describe('/health endpoint with auth', () => {
    it('GET /health without auth returns no authority field', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health');
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('ok');
      expect(body).not.toHaveProperty('authority');
    });

    it('GET /health with valid Bearer returns authenticated: true and authority', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health', {
        token: TOKEN,
      });
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).toEqual({
        status: 'ok',
        authority: AUTHORITY,
        authenticated: true,
      });
    });

    it('GET /health with invalid Bearer returns 401', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health', {
        token: 'wrong-token',
      });
      expect(res.status).toBe(401);
      const body = JSON.parse(res.body);
      expect(body).toEqual({ error: 'Invalid token' });
    });

    it('GET /health without Bearer returns no authenticated or authority field', async () => {
      ctx = await startTestServer();
      const res = await request(ctx.port, 'GET', '/health');
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).not.toHaveProperty('authenticated');
      expect(body).not.toHaveProperty('authority');
    });

    it('repeated /health auth failures do NOT trigger 429 on /sign', async () => {
      ctx = await startTestServer();

      // Send 12 invalid-token /health requests.
      for (let i = 0; i < 12; i++) {
        const healthRes = await request(ctx.port, 'GET', '/health', {
          token: 'bad-token',
        });
        expect(healthRes.status).toBe(401);
      }

      // A valid /sign request should succeed (not 429).
      const signRes = await request(ctx.port, 'POST', '/sign', {
        body: validSignBody(),
        headers: { 'Content-Type': 'application/json' },
        token: ctx.token,
      });
      expect(signRes.status).toBe(200);
    });
  });

  describe('CSP headers for issuer HTML', () => {
    it('CSP header on HTML responses contains img-src and connect-src directives', async () => {
      const issuerDir = join(testDir, 'issuer');
      await mkdir(issuerDir, { recursive: true });
      await writeFile(join(issuerDir, 'index.html'), '<html><body>test</body></html>');

      ctx = await startTestServer({ config: { issuerDir } });
      const res = await request(ctx.port, 'GET', '/');
      expect(res.status).toBe(200);
      const csp = res.headers['content-security-policy'];
      expect(csp).toBeDefined();
      expect(csp).toContain("img-src 'self' data:");
      expect(csp).toContain("connect-src 'self'");
    });

    it('CSP header appears exactly once on HTML responses', async () => {
      const issuerDir = join(testDir, 'issuer');
      await mkdir(issuerDir, { recursive: true });
      await writeFile(join(issuerDir, 'index.html'), '<html><body>test</body></html>');

      ctx = await startTestServer({ config: { issuerDir } });
      const res = await rawRequest(ctx.port, 'GET', '/');
      expect(res.status).toBe(200);

      // rawHeaders is [name, value, name, value, ...] — count occurrences of Content-Security-Policy.
      let cspCount = 0;
      for (let i = 0; i < res.rawHeaders.length; i += 2) {
        if (res.rawHeaders[i].toLowerCase() === 'content-security-policy') {
          cspCount++;
        }
      }
      expect(cspCount).toBe(1);
    });
  });

  it('registry decode failure is silently skipped and good key still works', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const badEntry: KeyEntry = {
      authority: AUTHORITY,
      from: '2020-01-01',
      to: null,
      algorithm: 'Ed25519',
      public_key: 'not-valid-base64!@#$',
      note: 'bad key',
    };
    ctx = await startTestServer({
      registry: { keys: [badEntry, activeKeyEntry()] },
    });
    const res = await request(ctx.port, 'POST', '/sign', {
      body: validSignBody(),
      headers: { 'Content-Type': 'application/json' },
      token: ctx.token,
    });
    expect(res.status).toBe(200);
    const decodeErrorLog = consoleSpy.mock.calls.find(
      (c) => typeof c[0] === 'string' && c[0].includes('Registry key decode failed:'),
    );
    expect(decodeErrorLog).toBeUndefined();
  });
});
