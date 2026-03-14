/**
 * YubiKey hardware signing adapter using yubico-piv-tool for Ed25519 operations.
 *
 * Communicates with a YubiKey PIV slot via the CLI tool to export certificates
 * and produce Ed25519 signatures.
 *
 * PIN exposure: yubico-piv-tool requires `-P <literal-pin>` on the command line.
 * There is no stdin, env-var, or file-based PIN input — the tool only accepts the
 * literal value via `-P`. The PIN will appear in `/proc/PID/cmdline` during the
 * signing window (milliseconds). This is accepted as residual risk for a single-user
 * localhost-only tool where only same-UID processes can read `/proc/PID/cmdline` on
 * hardened systems. Future alternative: `ykman piv` may support stdin PIN input.
 */

import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import type { ChildProcess } from 'node:child_process';
import { ED25519_SPKI_PREFIX } from '../registry.js';
import { sanitizeForError } from '../credential.js';
import { validateSignatureLength } from './signature.js';
import type { SigningAdapter } from './types.js';

type SpawnResult = {
  stdout: Buffer;
  stderr: string;
  code: number;
};

const MAX_STDERR_BYTES = 65_536;

/** Spawn a child process and collect stdout/stderr. Never rejects on non-zero exit. Rejects with timeout error if process exceeds timeoutMs. */
export function spawnAsync(command: string, args: string[], timeoutMs = 30_000): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(command, args);
    } catch (err) {
      reject(new Error(`Failed to spawn ${command}: ${err instanceof Error ? err.message : String(err)}`));
      return;
    }

    const stdoutChunks: Buffer[] = [];
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      try { child.kill('SIGTERM'); } catch {}
      killTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch {}
      }, 2000);
    }, timeoutMs);

    child.stdout?.on('data', (chunk: Buffer) => {
      stdoutChunks.push(chunk);
    });

    let stderrBytes = 0;
    child.stderr?.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_STDERR_BYTES) {
        stderr += chunk.toString();
      } else if (!stderr.endsWith('[truncated]')) {
        stderr += '\n[truncated]';
      }
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (timedOut) {
        reject(new Error(`${command} timed out after ${timeoutMs}ms`));
      } else {
        reject(new Error(`Failed to spawn ${command}: ${err.message}`));
      }
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (timedOut) {
        reject(new Error(`${command} timed out after ${timeoutMs}ms`));
        return;
      }
      resolve({
        stdout: Buffer.concat(stdoutChunks),
        stderr,
        code: code ?? 1,
      });
    });
  });
}

/** Validate a PIN: 6-8 printable ASCII characters (codes 0x20-0x7E). */
export function validatePin(pin: string): void {
  if (pin.length < 6 || pin.length > 8) {
    throw new Error(`PIN must be 6-8 characters, got ${pin.length}`);
  }
  for (let i = 0; i < pin.length; i++) {
    const code = pin.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      throw new Error(
        'PIN contains non-printable characters',
      );
    }
  }
}

/** Read a PIN interactively from the terminal with masked echo. */
export async function terminalPinReader(): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error('PIN entry requires an interactive terminal');
  }

  process.stderr.write('Enter YubiKey PIN: ');

  return new Promise<string>((resolve, reject) => {
    const chars: string[] = [];
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    const cleanup = () => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stderr.write('\n');
    };

    const onData = (data: string) => {
      for (const ch of data) {
        const code = ch.charCodeAt(0);

        // Ctrl+C — abort.
        if (code === 0x03) {
          cleanup();
          reject(new Error('PIN entry cancelled'));
          return;
        }

        // Ignore escape sequences.
        if (code === 0x1b) {
          return;
        }

        // Enter — done.
        if (ch === '\r' || ch === '\n') {
          cleanup();
          const pin = chars.join('');
          try {
            validatePin(pin);
            resolve(pin);
          } catch (err) {
            reject(err);
          }
          return;
        }

        // Backspace.
        if (code === 0x7f || code === 0x08) {
          if (chars.length > 0) {
            chars.pop();
            process.stderr.write('\b \b');
          }
          continue;
        }

        chars.push(ch);
        process.stderr.write('*');
      }
    };

    process.stdin.on('data', onData);
  });
}

/** Create a YubiKey PIV signing adapter. */
export function createYubiKeyAdapter(options?: {
  pivToolPath?: string;
  slot?: string;
  readPin?: () => Promise<string>;
}): SigningAdapter {
  const pivToolPath = options?.pivToolPath ?? 'yubico-piv-tool';
  const slot = options?.slot ?? '9c';
  const readPin = options?.readPin ?? terminalPinReader;

  let cachedKey: Uint8Array | null = null;

  return {
    async exportPublicKey(): Promise<Uint8Array> {
      if (cachedKey !== null) {
        return cachedKey;
      }

      const result = await spawnAsync(pivToolPath, [
        '-a', 'read-certificate',
        '-s', slot,
      ]);

      if (result.code !== 0) {
        console.error(`yubico-piv-tool read-certificate failed (exit ${result.code}): ${sanitizeForError(result.stderr.trim())}`);
        throw new Error('YubiKey certificate read failed');
      }

      const cert = new X509Certificate(result.stdout);
      const spkiDer = cert.publicKey.export({ type: 'spki', format: 'der' });

      if (spkiDer.length !== 44) {
        throw new Error(
          `Certificate public key is not Ed25519: expected 44-byte SPKI, got ${spkiDer.length} bytes`,
        );
      }

      for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
        if (spkiDer[i] !== ED25519_SPKI_PREFIX[i]) {
          throw new Error(
            'Certificate public key is not Ed25519: SPKI prefix mismatch',
          );
        }
      }

      const rawKey = new Uint8Array(spkiDer.buffer, spkiDer.byteOffset + ED25519_SPKI_PREFIX.length, 32);
      cachedKey = new Uint8Array(rawKey);
      return cachedKey;
    },

    async signBytes(data: Uint8Array): Promise<Uint8Array> {
      const pin = await readPin();

      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rhg-'));

      const tmpInPath = path.join(tmpDir, 'input.bin');
      const tmpOutPath = path.join(tmpDir, 'output.bin');

      try {
        const fd = await fs.open(tmpInPath, 'wx', 0o600);
        await fd.writeFile(Buffer.from(data));
        await fd.close();

        const result = await spawnAsync(pivToolPath, [
          '-a', 'verify-pin',
          '-a', 'sign-data',
          '-s', slot,
          '-A', 'ED25519',
          '-P', pin,
          '-i', tmpInPath,
          '-o', tmpOutPath,
        ]);

        if (result.code !== 0) {
          console.error(`yubico-piv-tool sign-data failed (exit ${result.code}): ${sanitizeForError(result.stderr.trim())}`);
          throw new Error('YubiKey signing operation failed');
        }

        await fs.chmod(tmpOutPath, 0o600);
        const sigBytes = await fs.readFile(tmpOutPath);

        return validateSignatureLength(new Uint8Array(sigBytes));
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true });
      }
    },
  };
}
