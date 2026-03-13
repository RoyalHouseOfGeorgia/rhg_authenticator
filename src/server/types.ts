import type { Registry } from '../registry.js';

/** Hardware signing adapter — the seam for testing. */
export type SigningAdapter = {
  exportPublicKey(): Promise<Uint8Array>;
  signBytes(data: Uint8Array): Promise<Uint8Array>;
};

export type IssuanceRecord = {
  timestamp: string;        // ISO 8601 (e.g., "2026-03-12T14:30:00Z")
  recipient: string;
  honor: string;
  detail: string;
  date: string;             // YYYY-MM-DD
  authority: string;
  payload_sha256: string;   // hex-encoded SHA-256 of canonical payload bytes
  signature_b64url: string; // Base64URL of the 64-byte signature
};

export type ServerConfig = {
  port: number;             // default 3141
  host: string;             // default '127.0.0.1'
  registryUrl: string;      // remote registry URL
  localRegistryPath: string; // fallback local path
  logPath: string;          // path to issuances.json
  issuerDir: string | null; // path to issuer HTML (null = placeholder)
  authority: string;        // resolved at startup from registry match
};

export type RegistryFetchResult = {
  registry: Registry;
  source: 'remote' | 'local';
  warning?: string;
};
