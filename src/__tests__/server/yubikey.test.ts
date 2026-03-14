import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ChildProcess } from 'node:child_process';
import { ED25519_SPKI_PREFIX } from '../../registry.js';

// Test key material.
const TEST_RAW_KEY = new Uint8Array(32);
TEST_RAW_KEY[0] = 0x42;
const TEST_SPKI = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX), Buffer.from(TEST_RAW_KEY)]);

// Hoisted mock functions (available before vi.mock factory runs).
const { mockSpawn, mockX509, mockMkdtemp, mockChmod, mockOpen, mockReadFile, mockRm } = vi.hoisted(() => ({
  mockSpawn: vi.fn(),
  mockX509: vi.fn(),
  mockMkdtemp: vi.fn(),
  mockChmod: vi.fn(),
  mockOpen: vi.fn(),
  mockReadFile: vi.fn(),
  mockRm: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  spawn: mockSpawn,
}));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    X509Certificate: mockX509,
  };
});

vi.mock('node:fs/promises', () => ({
  default: {
    mkdtemp: mockMkdtemp,
    chmod: mockChmod,
    open: mockOpen,
    readFile: mockReadFile,
    rm: mockRm,
  },
}));

import { createYubiKeyAdapter, validatePin, terminalPinReader, spawnAsync } from '../../server/yubikey.js';

// Helper to create a mock ChildProcess with controllable events.
function createMockProcess(opts: {
  stdout?: Buffer;
  stderr?: string;
  exitCode?: number;
  error?: Error;
}): ChildProcess {
  const proc = new EventEmitter() as ChildProcess;
  const stdoutEmitter = new EventEmitter();
  const stderrEmitter = new EventEmitter();
  (proc as unknown as Record<string, unknown>).stdout = stdoutEmitter;
  (proc as unknown as Record<string, unknown>).stderr = stderrEmitter;

  process.nextTick(() => {
    if (opts.error) {
      proc.emit('error', opts.error);
      return;
    }
    if (opts.stdout) {
      stdoutEmitter.emit('data', opts.stdout);
    }
    if (opts.stderr) {
      stderrEmitter.emit('data', Buffer.from(opts.stderr));
    }
    proc.emit('close', opts.exitCode ?? 0);
  });

  return proc;
}

describe('yubikey adapter', () => {
  beforeEach(() => {
    mockSpawn.mockReset();
    mockX509.mockReset();
    mockMkdtemp.mockReset();
    mockChmod.mockReset();
    mockOpen.mockReset();
    mockReadFile.mockReset();
    mockRm.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('exportPublicKey', () => {
    it('spawns correct command and parses X509 certificate to raw 32-byte key', async () => {
      const certPem = Buffer.from('FAKE-PEM-CERT');
      mockSpawn.mockReturnValue(
        createMockProcess({ stdout: certPem, exitCode: 0 }),
      );
      mockX509.mockImplementation(() => ({
        publicKey: {
          export: () => Buffer.from(TEST_SPKI),
        },
      }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });
      const key = await adapter.exportPublicKey();

      expect(mockSpawn).toHaveBeenCalledWith('yubico-piv-tool', [
        '-a', 'read-certificate',
        '-s', '9c',
      ]);
      expect(key).toEqual(TEST_RAW_KEY);
      expect(key.length).toBe(32);
    });

    it('rejects non-Ed25519 certificate (wrong SPKI prefix)', async () => {
      const wrongSpki = Buffer.alloc(44, 0xff);
      mockSpawn.mockReturnValue(
        createMockProcess({ stdout: Buffer.from('CERT'), exitCode: 0 }),
      );
      mockX509.mockImplementation(() => ({
        publicKey: { export: () => wrongSpki },
      }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.exportPublicKey()).rejects.toThrow(
        'Certificate public key is not Ed25519: SPKI prefix mismatch',
      );
    });

    it('rejects certificate with wrong SPKI length', async () => {
      const wrongLength = Buffer.alloc(50, 0x00);
      mockSpawn.mockReturnValue(
        createMockProcess({ stdout: Buffer.from('CERT'), exitCode: 0 }),
      );
      mockX509.mockImplementation(() => ({
        publicKey: { export: () => wrongLength },
      }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.exportPublicKey()).rejects.toThrow(
        'Certificate public key is not Ed25519: expected 44-byte SPKI',
      );
    });

    it('caches after first call — second call does not spawn', async () => {
      mockSpawn.mockReturnValue(
        createMockProcess({ stdout: Buffer.from('CERT'), exitCode: 0 }),
      );
      mockX509.mockImplementation(() => ({
        publicKey: { export: () => Buffer.from(TEST_SPKI) },
      }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      const key1 = await adapter.exportPublicKey();
      mockSpawn.mockClear();

      const key2 = await adapter.exportPublicKey();

      expect(mockSpawn).not.toHaveBeenCalled();
      expect(key1).toEqual(key2);
    });

    it('throws generic message and logs sanitized stderr on non-zero exit from read-certificate', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 1, stderr: 'No applet found' }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.exportPublicKey()).rejects.toThrow(
        'YubiKey certificate read failed',
      );
      expect(errorSpy).toHaveBeenCalledWith(
        'yubico-piv-tool read-certificate failed (exit 1): No applet found',
      );
      errorSpy.mockRestore();
    });

    it('sanitizes control characters from stderr before logging on read-certificate failure', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 1, stderr: 'fail\x00msg\x1b[31m' }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.exportPublicKey()).rejects.toThrow(
        'YubiKey certificate read failed',
      );
      expect(errorSpy).toHaveBeenCalledWith(
        'yubico-piv-tool read-certificate failed (exit 1): failmsg[31m',
      );
      errorSpy.mockRestore();
    });
  });

  describe('signBytes', () => {
    const setupFsMocks = () => {
      const mockFd = {
        writeFile: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
      };
      mockMkdtemp.mockResolvedValue('/tmp/rhg-test123');
      mockChmod.mockResolvedValue(undefined);
      mockOpen.mockResolvedValue(mockFd);
      mockRm.mockResolvedValue(undefined);
      return mockFd;
    };

    it('writes input file, spawns with correct args, reads back signature', async () => {
      const mockFd = setupFsMocks();
      const sig64 = Buffer.alloc(64, 0xab);
      mockReadFile.mockResolvedValue(sig64);

      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 0 }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '654321',
      });

      const inputData = new Uint8Array([1, 2, 3, 4]);
      const result = await adapter.signBytes(inputData);

      expect(result.length).toBe(64);

      expect(mockOpen).toHaveBeenCalledWith(
        '/tmp/rhg-test123/input.bin', 'wx', 0o600,
      );
      expect(mockFd.writeFile).toHaveBeenCalled();
      expect(mockFd.close).toHaveBeenCalled();

      expect(mockSpawn).toHaveBeenCalledWith('yubico-piv-tool', [
        '-a', 'verify-pin',
        '-a', 'sign-data',
        '-s', '9c',
        '-A', 'ED25519',
        '-P', '654321',
        '-i', '/tmp/rhg-test123/input.bin',
        '-o', '/tmp/rhg-test123/output.bin',
      ]);

      expect(mockChmod).toHaveBeenCalledTimes(1);
      expect(mockChmod).toHaveBeenCalledWith('/tmp/rhg-test123/output.bin', 0o600);
      expect(mockReadFile).toHaveBeenCalledWith('/tmp/rhg-test123/output.bin');
    });

    it('cleans up temp directory after success', async () => {
      setupFsMocks();
      mockReadFile.mockResolvedValue(Buffer.alloc(64, 0xab));
      mockSpawn.mockReturnValue(createMockProcess({ exitCode: 0 }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await adapter.signBytes(new Uint8Array([1]));

      expect(mockRm).toHaveBeenCalledWith('/tmp/rhg-test123', {
        recursive: true,
        force: true,
      });
    });

    it('cleans up temp directory after failure', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      setupFsMocks();
      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 1, stderr: 'auth failed' }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.signBytes(new Uint8Array([1]))).rejects.toThrow();

      expect(mockRm).toHaveBeenCalledWith('/tmp/rhg-test123', {
        recursive: true,
        force: true,
      });
      errorSpy.mockRestore();
    });

    it('calls validateSignatureLength on spawn output — 64-byte output passes', async () => {
      setupFsMocks();
      const sig64 = Buffer.alloc(64);
      sig64[0] = 0xde;
      sig64[63] = 0xad;
      mockReadFile.mockResolvedValue(sig64);
      mockSpawn.mockReturnValue(createMockProcess({ exitCode: 0 }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      const result = await adapter.signBytes(new Uint8Array([1]));
      expect(result.length).toBe(64);
      expect(result[0]).toBe(0xde);
      expect(result[63]).toBe(0xad);
    });

    it('rejects when validateSignatureLength fails on wrong-length output', async () => {
      setupFsMocks();
      mockReadFile.mockResolvedValue(Buffer.alloc(48));
      mockSpawn.mockReturnValue(createMockProcess({ exitCode: 0 }));

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.signBytes(new Uint8Array([1]))).rejects.toThrow(
        'Expected 64-byte Ed25519 signature, got 48 bytes',
      );
    });

    it('reports clear error when command not found (spawn error event)', async () => {
      setupFsMocks();
      const errProc = new EventEmitter() as ChildProcess;
      const stdoutEmitter = new EventEmitter();
      const stderrEmitter = new EventEmitter();
      (errProc as unknown as Record<string, unknown>).stdout = stdoutEmitter;
      (errProc as unknown as Record<string, unknown>).stderr = stderrEmitter;
      process.nextTick(() => {
        errProc.emit('error', new Error('spawn yubico-piv-tool ENOENT'));
      });
      mockSpawn.mockReturnValue(errProc);

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.signBytes(new Uint8Array([1]))).rejects.toThrow(
        'Failed to spawn yubico-piv-tool',
      );
    });

    it('throws generic message and logs sanitized stderr on non-zero exit', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      setupFsMocks();
      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 3, stderr: 'Authentication method blocked' }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.signBytes(new Uint8Array([1]))).rejects.toThrow(
        'YubiKey signing operation failed',
      );
      expect(errorSpy).toHaveBeenCalledWith(
        'yubico-piv-tool sign-data failed (exit 3): Authentication method blocked',
      );
      errorSpy.mockRestore();
    });

    it('sanitizes control characters from stderr before logging', async () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      setupFsMocks();
      mockSpawn.mockReturnValue(
        createMockProcess({ exitCode: 1, stderr: 'error\x00with\x1bcontrol' }),
      );

      const adapter = createYubiKeyAdapter({
        readPin: async () => '123456',
      });

      await expect(adapter.signBytes(new Uint8Array([1]))).rejects.toThrow(
        'YubiKey signing operation failed',
      );
      expect(errorSpy).toHaveBeenCalledWith(
        'yubico-piv-tool sign-data failed (exit 1): errorwithcontrol',
      );
      errorSpy.mockRestore();
    });
  });
});

describe('validatePin', () => {
  it('accepts a valid 6-character PIN', () => {
    expect(() => validatePin('123456')).not.toThrow();
  });

  it('accepts a valid 8-character PIN', () => {
    expect(() => validatePin('12345678')).not.toThrow();
  });

  it('accepts a 7-character PIN with printable special chars', () => {
    expect(() => validatePin('ab!@#cd')).not.toThrow();
  });

  it('rejects empty PIN', () => {
    expect(() => validatePin('')).toThrow('PIN must be 6-8 characters, got 0');
  });

  it('rejects 5-character PIN (below minimum)', () => {
    expect(() => validatePin('12345')).toThrow('PIN must be 6-8 characters, got 5');
  });

  it('rejects 9-character PIN (above maximum)', () => {
    expect(() => validatePin('123456789')).toThrow('PIN must be 6-8 characters, got 9');
  });

  it('rejects PIN with non-printable characters', () => {
    expect(() => validatePin('123\x01\x0256')).toThrow(
      'PIN contains non-printable characters',
    );
  });

  it('rejects PIN with DEL character (0x7F)', () => {
    expect(() => validatePin('12345\x7f')).toThrow(
      'PIN contains non-printable characters',
    );
  });
});

describe('terminalPinReader', () => {
  it('throws when stdin is not a TTY', async () => {
    const originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });

    try {
      await expect(terminalPinReader()).rejects.toThrow(
        'PIN entry requires an interactive terminal',
      );
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
    }
  });

  // Helper to install a mock stdin for interactive PIN tests.
  function withMockStdin(
    testFn: (emitData: (data: string) => void) => Promise<void>,
  ): () => Promise<void> {
    return async () => {
      const originalIsTTY = process.stdin.isTTY;
      const originalSetRawMode = process.stdin.setRawMode;
      const originalResume = process.stdin.resume;
      const originalPause = process.stdin.pause;
      const originalSetEncoding = process.stdin.setEncoding;

      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
      process.stdin.setRawMode = vi.fn().mockReturnValue(process.stdin);
      process.stdin.resume = vi.fn().mockReturnValue(process.stdin);
      process.stdin.pause = vi.fn().mockReturnValue(process.stdin);
      process.stdin.setEncoding = vi.fn().mockReturnValue(process.stdin);
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

      const emitData = (data: string) => {
        process.stdin.emit('data', data);
      };

      try {
        await testFn(emitData);
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
        process.stdin.setRawMode = originalSetRawMode;
        process.stdin.resume = originalResume;
        process.stdin.pause = originalPause;
        process.stdin.setEncoding = originalSetEncoding;
        stderrSpy.mockRestore();
      }
    };
  }

  it('rejects with "PIN entry cancelled" when Ctrl+C (0x03) is sent', withMockStdin(async (emitData) => {
    const promise = terminalPinReader();
    emitData('\x03');
    await expect(promise).rejects.toThrow('PIN entry cancelled');
  }));

  it('discards escape sequence characters (arrow up \\x1b[A does not appear in PIN)', withMockStdin(async (emitData) => {
    const promise = terminalPinReader();
    emitData('12');
    emitData('\x1b[A');
    emitData('3456');
    emitData('\r');
    const pin = await promise;
    expect(pin).toBe('123456');
  }));

  it('rejects PIN containing Ctrl+D (0x04) via validatePin since it is non-printable', withMockStdin(async (emitData) => {
    const promise = terminalPinReader();
    emitData('123\x0456\r');
    await expect(promise).rejects.toThrow('PIN contains non-printable characters');
  }));

  it('resolves with valid PIN on Enter after typing', withMockStdin(async (emitData) => {
    const promise = terminalPinReader();
    emitData('abcdef\r');
    const pin = await promise;
    expect(pin).toBe('abcdef');
  }));

  it('handles backspace correctly', withMockStdin(async (emitData) => {
    const promise = terminalPinReader();
    emitData('1234567\x7f\r');
    const pin = await promise;
    expect(pin).toBe('123456');
  }));
});

describe('spawnAsync timeout', () => {
  beforeEach(() => {
    mockSpawn.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('rejects with timeout error when process exceeds timeoutMs', async () => {
    vi.useFakeTimers();
    const proc = new EventEmitter() as ChildProcess;
    (proc as unknown as Record<string, unknown>).stdout = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stderr = new EventEmitter();
    const killMock = vi.fn();
    (proc as unknown as Record<string, unknown>).kill = killMock;
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('test-cmd', ['arg'], 100);

    await vi.advanceTimersByTimeAsync(100);
    expect(killMock).toHaveBeenCalledWith('SIGTERM');

    proc.emit('close', null);
    await expect(promise).rejects.toThrow('test-cmd timed out after 100ms');
  });

  it('resolves normally when process completes within timeout', async () => {
    const proc = createMockProcess({ stdout: Buffer.from('ok'), exitCode: 0 });
    mockSpawn.mockReturnValue(proc);

    const result = await spawnAsync('test-cmd', ['arg'], 5000);
    expect(result.code).toBe(0);
    expect(result.stdout.toString()).toBe('ok');
  });

  it('sends SIGKILL after 2s grace period if SIGTERM does not stop process', async () => {
    vi.useFakeTimers();
    const proc = new EventEmitter() as ChildProcess;
    (proc as unknown as Record<string, unknown>).stdout = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stderr = new EventEmitter();
    const killMock = vi.fn();
    (proc as unknown as Record<string, unknown>).kill = killMock;
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('test-cmd', [], 100);

    await vi.advanceTimersByTimeAsync(100);
    expect(killMock).toHaveBeenCalledWith('SIGTERM');
    expect(killMock).not.toHaveBeenCalledWith('SIGKILL');

    await vi.advanceTimersByTimeAsync(2000);
    expect(killMock).toHaveBeenCalledWith('SIGKILL');

    proc.emit('close', null);
    await expect(promise).rejects.toThrow('timed out');

    vi.useRealTimers();
  });

  it('rejects via error event with timeout message when timed out', async () => {
    vi.useFakeTimers();
    const proc = new EventEmitter() as ChildProcess;
    (proc as unknown as Record<string, unknown>).stdout = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stderr = new EventEmitter();
    const killMock = vi.fn();
    (proc as unknown as Record<string, unknown>).kill = killMock;
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('slow-cmd', [], 50);

    await vi.advanceTimersByTimeAsync(50);

    proc.emit('error', new Error('killed'));
    await expect(promise).rejects.toThrow('slow-cmd timed out after 50ms');
  });

  it('settled guard prevents double resolution on close after error', async () => {
    const proc = new EventEmitter() as ChildProcess;
    (proc as unknown as Record<string, unknown>).stdout = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stderr = new EventEmitter();
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('test-cmd', [], 5000);

    proc.emit('error', new Error('spawn ENOENT'));
    proc.emit('close', 0);

    await expect(promise).rejects.toThrow('Failed to spawn test-cmd: spawn ENOENT');
  });

  it('uses default 30s timeout when not specified', async () => {
    vi.useFakeTimers();
    const proc = new EventEmitter() as ChildProcess;
    (proc as unknown as Record<string, unknown>).stdout = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stderr = new EventEmitter();
    const killMock = vi.fn();
    (proc as unknown as Record<string, unknown>).kill = killMock;
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('test-cmd', []);

    await vi.advanceTimersByTimeAsync(29_900);
    expect(killMock).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(100);
    expect(killMock).toHaveBeenCalledWith('SIGTERM');

    proc.emit('close', null);
    await expect(promise).rejects.toThrow('timed out');

    vi.useRealTimers();
  });

  it('truncates stderr when output exceeds 64KB', async () => {
    const proc = new EventEmitter() as ChildProcess;
    const stdoutEmitter = new EventEmitter();
    const stderrEmitter = new EventEmitter();
    (proc as unknown as Record<string, unknown>).stdout = stdoutEmitter;
    (proc as unknown as Record<string, unknown>).stderr = stderrEmitter;
    mockSpawn.mockReturnValue(proc);

    const promise = spawnAsync('test-cmd', ['arg'], 10_000);

    // Emit >64KB of stderr in chunks
    const chunkSize = 16_384;
    const totalChunks = 6; // 6 * 16KB = 96KB > 64KB
    for (let i = 0; i < totalChunks; i++) {
      stderrEmitter.emit('data', Buffer.alloc(chunkSize, 0x41 + i));
    }
    proc.emit('close', 0);

    const result = await promise;
    expect(result.stderr.endsWith('[truncated]')).toBe(true);
    // Should have captured the first 64KB worth of data plus truncation marker
    expect(result.stderr.length).toBeLessThan(96 * 1024 + 20);
  });
});
