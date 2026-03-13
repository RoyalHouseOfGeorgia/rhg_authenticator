import { createHash, timingSafeEqual } from 'node:crypto';
import { type IncomingMessage, type ServerResponse } from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { sanitizeForError } from '../credential.js';
import { handleSign } from './sign.js';
import { isKeyActive } from './key-match.js';
import type { SigningAdapter, ServerConfig } from './types.js';
import type { Registry } from '../registry.js';
import type { SignRequest, SignResponse, SignError } from './sign.js';

const SIGN_REQUEST_FIELDS: readonly (keyof SignRequest)[] = [
  'recipient',
  'honor',
  'detail',
  'date',
] as const;

function validateSignRequest(parsed: unknown): SignRequest {
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed)
  ) {
    throw new Error('Request body must be a JSON object');
  }
  const obj = parsed as Record<string, unknown>;
  const result: Partial<SignRequest> = {};
  for (const field of SIGN_REQUEST_FIELDS) {
    if (!(field in obj) || typeof obj[field] !== 'string') {
      throw new Error(`Field "${field}" must be a string`);
    }
    result[field] = obj[field] as string;
  }
  return result as SignRequest;
}

export type ServerDeps = {
  adapter: SigningAdapter;
  config: ServerConfig;
  cachedPublicKey: Uint8Array;
  registryRef: { current: Registry }; // mutable ref, updated by background refresh
  listeningPort: { current: number }; // mutable ref — updated after server.listen resolves when port is 0 (ephemeral)
};

const MAX_BODY_BYTES = 64 * 1024; // 64KB
const BODY_READ_TIMEOUT_MS = 5000;
const MAX_STATIC_FILE_BYTES = 10 * 1024 * 1024; // 10MB
const MAX_SIGN_QUEUE_DEPTH = 5;

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store',
};

const MIME_MAP: Record<string, string> = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const PLACEHOLDER_HTML =
  '<html><body><h1>RHG Issuer</h1><p>Issuer interface coming soon.</p></body></html>';

function verifyToken(provided: string, expected: string): boolean {
  const a = createHash('sha256').update(provided).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

function jsonResponse(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json',
    ...extraHeaders,
  });
  res.end(json);
}

function extractBearerToken(req: IncomingMessage): string | null {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice(7);
}

function readBody(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let byteCount = 0;
    let aborted = false;
    const socket = req.socket;

    const timer = setTimeout(() => {
      aborted = true;
      req.removeAllListeners('data');
      req.removeAllListeners('end');
      req.removeAllListeners('error');
      jsonResponse(res, 408, { error: 'Request timeout' });
      res.once('close', () => {
        if (socket && !socket.destroyed) socket.destroy();
      });
      resolve(null);
    }, BODY_READ_TIMEOUT_MS);

    req.on('data', (chunk: Buffer) => {
      if (aborted) return;
      byteCount += chunk.length;
      if (byteCount > MAX_BODY_BYTES) {
        aborted = true;
        clearTimeout(timer);
        req.removeAllListeners('data');
        req.removeAllListeners('end');
        req.removeAllListeners('error');
        jsonResponse(res, 413, { error: 'Request body too large' });
        res.once('close', () => {
          if (socket && !socket.destroyed) socket.destroy();
        });
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });

    req.on('error', () => {
      if (aborted) return;
      clearTimeout(timer);
      resolve(null);
    });
  });
}

function stripBom(buf: Buffer): Buffer {
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.subarray(3);
  }
  return buf;
}

async function serveStaticFile(
  issuerDir: string,
  urlPath: string,
  res: ServerResponse,
): Promise<void> {
  const safePath = urlPath === '/' ? '/index.html' : urlPath;
  const requested = path.resolve(issuerDir, '.' + safePath);

  let resolvedDir: string;
  let resolvedFile: string;
  try {
    resolvedDir = await fs.realpath(issuerDir);
    resolvedFile = await fs.realpath(requested);
  } catch {
    jsonResponse(res, 404, { error: 'Not found' });
    return;
  }

  if (!resolvedFile.startsWith(resolvedDir + path.sep) && resolvedFile !== resolvedDir) {
    jsonResponse(res, 404, { error: 'Not found' });
    return;
  }

  // Open file descriptor — all subsequent operations use the same fd,
  // eliminating TOCTOU races between stat and read.
  let fh: import('node:fs/promises').FileHandle;
  try {
    fh = await fs.open(resolvedFile, 'r');
  } catch {
    jsonResponse(res, 404, { error: 'Not found' });
    return;
  }

  try {
    const stat = await fh.stat();

    // Defense-in-depth: reject directories (realpath already resolved symlinks).
    if (!stat.isFile()) {
      jsonResponse(res, 404, { error: 'Not found' });
      return;
    }

    if (stat.size > MAX_STATIC_FILE_BYTES) {
      jsonResponse(res, 413, { error: 'File too large' });
      return;
    }

    // Bounded read: allocate stat.size + 1 to detect file growth between stat and read.
    const buf = Buffer.alloc(Math.min(stat.size, MAX_STATIC_FILE_BYTES) + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);

    if (bytesRead > MAX_STATIC_FILE_BYTES) {
      jsonResponse(res, 413, { error: 'File too large' });
      return;
    }

    const content = buf.subarray(0, bytesRead);
    const ext = path.extname(resolvedFile).toLowerCase();
    const contentType = MIME_MAP[ext] ?? 'application/octet-stream';
    const csp = ext === '.html'
      ? "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
      : "default-src 'none'";
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': contentType,
      'Content-Security-Policy': csp,
    });
    res.end(content);
  } finally {
    await fh.close();
  }
}

export function createRequestHandler(
  deps: ServerDeps,
  bearerToken: string,
  logPath: string,
): (req: IncomingMessage, res: ServerResponse) => void {
  let signQueue: Promise<void> = Promise.resolve();
  let signQueueDepth = 0;

  // Global auth-failure rate limiter. On a localhost single-user signing tool,
  // all requests come from the same host, so per-IP tracking is unnecessary.
  let authFailCount = 0;
  let authFailBackoffUntil = 0; // monotonic ms (performance.now())

  return (req: IncomingMessage, res: ServerResponse) => {
    void handleRequest(req, res);

    async function handleRequest(
      req: IncomingMessage,
      res: ServerResponse,
    ): Promise<void> {
      const method = req.method ?? '';
      const url = req.url ?? '/';
      // Strip query string for route matching.
      const pathname = url.split('?')[0];

      // L4: Cross-origin rejection — block non-localhost origins.
      // Built per-request from mutable ref so ephemeral port (0) is correct
      // after server.listen resolves. The set is tiny (3 entries), negligible cost.
      const origin = req.headers['origin'];
      if (method === 'POST' && pathname === '/sign') {
        // POST /sign requires Origin (defense-in-depth against non-browser CSRF).
        // Non-browser clients (curl, scripts) must send Origin explicitly.
        const port = deps.listeningPort.current;
        if (
          !origin ||
          (origin !== `http://127.0.0.1:${port}` &&
           origin !== `http://localhost:${port}` &&
           origin !== `http://[::1]:${port}`)
        ) {
          jsonResponse(res, 403, { error: origin ? 'Cross-origin request denied' : 'Origin header required' });
          return;
        }
      } else if (origin) {
        // Non-/sign routes: still reject foreign origins when header is present
        const port = deps.listeningPort.current;
        if (origin !== `http://127.0.0.1:${port}` && origin !== `http://localhost:${port}` && origin !== `http://[::1]:${port}`) {
          jsonResponse(res, 403, { error: 'Cross-origin request denied' });
          return;
        }
      }

      // L8: /health exposes no CORS headers; browsers block cross-origin reads by default.
      // --- GET /health ---
      if (pathname === '/health') {
        if (method !== 'GET') {
          jsonResponse(res, 405, { error: 'Method not allowed' }, { Allow: 'GET' });
          return;
        }
        jsonResponse(res, 200, { status: 'ok' });
        return;
      }

      // --- POST /sign ---
      if (pathname === '/sign') {
        if (method !== 'POST') {
          jsonResponse(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
          return;
        }

        // Auth check — always exercise full SHA-256 + timingSafeEqual path.
        const token = extractBearerToken(req);
        if (!verifyToken(token ?? '', bearerToken)) {
          const now = performance.now();
          if (now < authFailBackoffUntil) {
            const remainingSec = Math.ceil((authFailBackoffUntil - now) / 1000);
            jsonResponse(res, 429, { error: 'Too many auth failures' }, { 'Retry-After': String(remainingSec) });
            return;
          }
          authFailCount++;
          if (authFailCount >= 5) {
            const delay = Math.min(1000 * 2 ** (authFailCount - 5), 30_000);
            authFailBackoffUntil = now + delay;
          }
          jsonResponse(res, 401, { error: 'Unauthorized' });
          return;
        }
        // Valid auth — reset rate limiter.
        authFailCount = 0;
        authFailBackoffUntil = 0;

        // Content-Type check.
        if (!req.headers['content-type']?.startsWith('application/json')) {
          jsonResponse(res, 415, { error: 'Unsupported media type' });
          return;
        }

        // Read body.
        const rawBody = await readBody(req, res);
        if (rawBody === null) return; // Already responded (timeout or too large).

        // Empty body check.
        if (rawBody.length === 0) {
          jsonResponse(res, 400, { error: 'Empty request body' });
          return;
        }

        // Strip BOM and parse JSON.
        const body = stripBom(rawBody);
        let parsed: unknown;
        try {
          parsed = JSON.parse(body.toString('utf-8'));
        } catch {
          jsonResponse(res, 400, { error: 'Invalid JSON' });
          return;
        }

        // Validate request body structure.
        let signRequest: SignRequest;
        try {
          signRequest = validateSignRequest(parsed);
        } catch (err) {
          console.error(
            'Sign request validation failed:',
            sanitizeForError((err as Error).message),
          );
          jsonResponse(res, 400, { error: 'Invalid request body' });
          return;
        }

        // Pre-sign registry check: key must be active.
        const registry = deps.registryRef.current;
        if (!isKeyActive(registry, deps.cachedPublicKey)) {
          jsonResponse(res, 403, {
            error: 'Key not active in current registry',
          });
          return;
        }

        // M2/M3: Queue depth cap.
        if (signQueueDepth >= MAX_SIGN_QUEUE_DEPTH) {
          jsonResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '1' });
          return;
        }
        signQueueDepth++;

        // Mutex-serialized signing.
        const myResult = new Promise<SignResponse | SignError>(
          (resolve, reject) => {
            signQueue = signQueue.catch(() => {}).then(async () => {
              try {
                resolve(
                  await handleSign(
                    signRequest,
                    deps.adapter,
                    deps.cachedPublicKey,
                    deps.config.authority,
                    logPath,
                  ),
                );
              } catch (e) {
                reject(e);
              } finally {
                signQueueDepth--;
              }
            });
          },
        );

        let result: SignResponse | SignError;
        try {
          result = await myResult;
        } catch (err) {
          console.error('Sign handler error:', sanitizeForError((err as Error).message));
          jsonResponse(res, 500, { error: 'Internal server error' });
          return;
        }

        if ('error' in result && 'code' in result) {
          const status = result.code === 'VALIDATION_FAILED' ? 400 : 500;
          jsonResponse(res, status, { error: result.error });
          return;
        }

        jsonResponse(res, 200, result);
        return;
      }

      // --- GET / (root) ---
      if (pathname === '/') {
        if (method !== 'GET') {
          jsonResponse(res, 405, { error: 'Method not allowed' }, { Allow: 'GET' });
          return;
        }
        if (deps.config.issuerDir === null) {
          res.writeHead(200, {
            ...SECURITY_HEADERS,
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'none'",
          });
          res.end(PLACEHOLDER_HTML);
          return;
        }
        await serveStaticFile(deps.config.issuerDir, pathname, res);
        return;
      }

      // --- Static files from issuerDir (sub-paths) ---
      if (deps.config.issuerDir !== null && method === 'GET') {
        await serveStaticFile(deps.config.issuerDir, pathname, res);
        return;
      }

      // --- 404 ---
      jsonResponse(res, 404, { error: 'Not found' });
    }
  };
}
