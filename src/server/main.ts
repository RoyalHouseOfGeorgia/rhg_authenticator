import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { base64urlEncode } from '../base64url.js';
import { sanitizeForError } from '../credential.js';
import { fetchAndValidateRegistry } from './registry-fetch.js';
import { createYubiKeyAdapter } from './yubikey.js';
import { createRequestHandler } from './http.js';
import { findMatchingAuthority } from './key-match.js';
import type { SigningAdapter, ServerConfig } from './types.js';
import type { Registry } from '../registry.js';

/**
 * Start the RHG signing server.
 *
 * Generates a bearer token, resolves the signing key against the registry,
 * and starts an HTTP server with background registry refresh.
 */
export async function startServer(options?: {
  config?: Partial<ServerConfig>;
  adapter?: SigningAdapter;
  now?: Date;
}): Promise<{ server: http.Server; port: number; token: string; close: () => void }> {
  const token = crypto.randomBytes(32).toString('hex');

  const defaults: ServerConfig = {
    port: 3141,
    host: '127.0.0.1',
    registryUrl: 'https://verify.royalhouseofgeorgia.ge/keys/registry.json',
    localRegistryPath: './keys/registry.json',
    logPath: './issuances.json',
    issuerDir: null,
    authority: '',
  };
  const config = { ...defaults, ...options?.config };

  const adapter = options?.adapter ?? createYubiKeyAdapter();
  const adapterKey = await adapter.exportPublicKey();

  const result = await fetchAndValidateRegistry(config.registryUrl, config.localRegistryPath);
  const registry = result.registry;

  const todayDate = (options?.now ?? new Date()).toISOString().slice(0, 10);
  const matchedAuthority = findMatchingAuthority(registry, adapterKey, todayDate);

  if (matchedAuthority === undefined) {
    throw new Error('No active registry entry matches the YubiKey public key');
  }

  config.authority = matchedAuthority.normalize('NFC');

  const registryRef: { current: Registry } = { current: registry };
  const portRef = { current: config.port };

  const handler = createRequestHandler(
    { adapter, config, cachedPublicKey: adapterKey, registryRef, listeningPort: portRef },
    token,
    config.logPath,
  );

  const server = http.createServer(handler);
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;

  const refreshInterval = setInterval(async () => {
    try {
      const refreshResult = await fetchAndValidateRegistry(config.registryUrl, config.localRegistryPath);
      registryRef.current = refreshResult.registry;
      if (refreshResult.warning) console.error(`Registry refresh warning: ${sanitizeForError(refreshResult.warning)}`);
    } catch (err) {
      console.error(`Registry refresh failed: ${sanitizeForError(err instanceof Error ? err.message : String(err))}`);
    }
  }, 60_000);
  refreshInterval.unref();

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, () => {
      server.removeListener('error', reject);
      portRef.current = (server.address() as AddressInfo).port;
      resolve();
    });
  });

  const keyB64url = base64urlEncode(adapterKey);
  const banner = [
    `RHG Signing Server running on http://${config.host}:${portRef.current}`,
    `Bearer token fingerprint: ${crypto.createHash('sha256').update(token).digest('hex').slice(0, 16)}`,
    `YubiKey key: ${keyB64url} (matched: ${config.authority})`,
    `Registry: ${result.source}${result.warning ? ` [${result.warning}]` : ''}`,
  ].join('\n');
  console.error(banner);

  const close = () => {
    clearInterval(refreshInterval);
    server.close();
  };

  return { server, port: portRef.current, token, close };
}
