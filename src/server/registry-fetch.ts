import dns from 'node:dns';
import fs from 'node:fs/promises';
import { sanitizeForError } from '../credential.js';
import { validateRegistry } from '../registry.js';
import type { Registry } from '../registry.js';
import type { RegistryFetchResult } from './types.js';

/** Maximum registry response size in bytes (1 MB). */
export const MAX_REGISTRY_BYTES = 1_048_576;

/**
 * Fetch registry from remote URL with local file fallback.
 *
 * - Remote success: parse JSON, validate, return source 'remote'.
 * - Remote non-2xx: fall back to local with warning including HTTP status.
 * - Network/timeout error: fall back to local with warning.
 * - Invalid JSON or schema from remote: throw (no fallback).
 * - Both unavailable: throw descriptive error.
 */
/** Reject non-HTTPS URLs and URLs targeting localhost/private IP ranges. */
function validateRegistryUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid registry URL: ${sanitizeForError(url).slice(0, 200)}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`Registry URL must use HTTPS: ${sanitizeForError(url).slice(0, 200)}`);
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, ''); // strip brackets from IPv6
  const blockedHosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0', '::'];
  if (blockedHosts.includes(hostname)) {
    throw new Error(`Registry URL must not target localhost: ${sanitizeForError(url).slice(0, 200)}`);
  }


}

function isPrivateIp(ip: string): boolean {
  // IPv4
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [, a, b] = v4.map(Number);
    return (
      a === 127 ||
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    );
  }
  // IPv6
  const lower = ip.toLowerCase();
  return (
    lower === '::1' ||
    lower === '::' ||
    lower.startsWith('fe80:') ||
    lower.startsWith('fc') || lower.startsWith('fd') ||  // fc00::/7 unique local
    lower.startsWith('::ffff:127.') ||
    lower.startsWith('::ffff:10.') ||
    lower.startsWith('::ffff:192.168.') ||
    lower.startsWith('::ffff:172.') // simplified; could be more precise
  );
}

export async function validateResolvedIp(hostname: string): Promise<void> {
  const { address } = await dns.promises.lookup(hostname);
  if (isPrivateIp(address)) {
    throw new Error(`Registry hostname resolved to private IP: ${address}`);
  }
}

export async function fetchAndValidateRegistry(
  remoteUrl: string,
  localPath: string,
  fetchFn?: typeof globalThis.fetch,
): Promise<RegistryFetchResult> {
  validateRegistryUrl(remoteUrl);
  const hostname = new URL(remoteUrl).hostname.replace(/^\[|\]$/g, '');
  await validateResolvedIp(hostname);
  const doFetch = fetchFn ?? globalThis.fetch;

  let response: Response;
  try {
    response = await doFetch(remoteUrl, {
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err: unknown) {
    const warning = isTimeoutError(err)
      ? 'Registry fetch timed out'
      : 'Registry fetch failed';
    return loadLocalFallback(localPath, warning);
  }

  if (!response.ok) {
    const warning = `Registry returned HTTP ${response.status}, using local fallback`;
    return loadLocalFallback(localPath, warning);
  }

  // Remote responded 2xx — parse and validate. Failures here are content
  // errors and must NOT fall back to local (stale local data would mask a
  // broken remote).

  // Check Content-Length before reading body.
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null) {
    const length = parseInt(contentLength, 10);
    if (!Number.isNaN(length) && length > MAX_REGISTRY_BYTES) {
      throw new Error(`Registry response too large: Content-Length ${length} exceeds ${MAX_REGISTRY_BYTES} bytes`);
    }
  }

  let body: string;
  try {
    const buf = await response.arrayBuffer();
    if (buf.byteLength > MAX_REGISTRY_BYTES) {
      throw new Error(`Registry response too large: ${buf.byteLength} bytes exceeds ${MAX_REGISTRY_BYTES} bytes`);
    }
    body = new TextDecoder().decode(buf);
  } catch (err) {
    // Re-throw our own size-limit errors; wrap unexpected read failures.
    if (err instanceof Error && err.message.startsWith('Registry response too large')) {
      throw err;
    }
    const detail = err instanceof Error ? err.message : String(err);
    const safeDetail = sanitizeForError(detail).slice(0, 200);
    throw new Error(`Registry response could not be processed: ${safeDetail}`, { cause: err });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : String(err);
    const safeMessage = sanitizeForError(message).slice(0, 200);
    throw new Error(`Registry JSON parse error: ${safeMessage}`);
  }

  const registry = validateRegistry(parsed);
  return { registry, source: 'remote' };
}

function isTimeoutError(err: unknown): boolean {
  if (err instanceof Error && err.name === 'TimeoutError') {
    return true;
  }
  if (
    err instanceof TypeError &&
    typeof (err as { cause?: unknown }).cause === 'object' &&
    (err as { cause?: { name?: unknown } }).cause !== null &&
    (err as { cause: { name?: unknown } }).cause.name === 'TimeoutError'
  ) {
    return true;
  }
  return false;
}

async function loadLocalFallback(
  localPath: string,
  warning: string,
): Promise<RegistryFetchResult> {
  let content: string;
  try {
    content = await fs.readFile(localPath, 'utf-8');
  } catch (err: unknown) {
    const detail = err instanceof Error ? err.message : String(err);
    const safeDetail = sanitizeForError(detail).slice(0, 200);
    throw new Error(
      `Registry unavailable: remote failed and local file unreadable: ${safeDetail}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (err: unknown) {
    const detail = err instanceof Error ? err.message : String(err);
    const safeDetail = sanitizeForError(detail).slice(0, 200);
    throw new Error(
      `Registry unavailable: remote failed and local file has invalid JSON: ${safeDetail}`,
    );
  }

  const registry = validateRegistry(parsed);
  return { registry, source: 'local', warning };
}
