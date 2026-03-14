import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
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
  tokenFilePath?: string;
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
      const todayDate = new Date().toISOString().slice(0, 10);
      const stillActive = findMatchingAuthority(refreshResult.registry, adapterKey, todayDate);
      if (stillActive === undefined) {
        console.error('WARNING: YubiKey public key no longer active in refreshed registry — new signing requests will be rejected');
      }
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
      const addr = server.address();
      if (!addr || typeof addr === 'string') throw new Error('Failed to determine listening port');
      portRef.current = addr.port;
      resolve();
    });
  });

  const tokenFilePath = options?.tokenFilePath;
  if (tokenFilePath !== undefined) {
    const parentDir = path.dirname(tokenFilePath);
    try {
      fs.accessSync(parentDir, fs.constants.W_OK);
    } catch {
      throw new Error(`Cannot write token file: parent directory does not exist or is not writable: ${parentDir}`);
    }
    fs.writeFileSync(tokenFilePath, token + '\n', { mode: 0o600 });
  }

  const keyB64url = base64urlEncode(adapterKey);
  const tokenLine = tokenFilePath !== undefined
    ? `Bearer token written to: ${tokenFilePath}`
    : `Bearer token: ${token}`;
  const banner = [
    `RHG Signing Server running on http://${config.host}:${portRef.current}`,
    tokenLine,
    `Token fingerprint: ${crypto.createHash('sha256').update(token).digest('hex').slice(0, 16)}`,
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
