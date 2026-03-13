import { describe, expect, it, afterEach, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { IssuanceRecord } from '../../server/types.js';
import { appendIssuanceRecord, readIssuanceLog } from '../../server/log.js';

let tmpDir: string | undefined;

async function makeTmpDir(): Promise<string> {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'log-test-'));
  return tmpDir;
}

function logPath(dir: string): string {
  return path.join(dir, 'issuances.json');
}

function makeRecord(overrides: Partial<IssuanceRecord> = {}): IssuanceRecord {
  return {
    timestamp: '2026-03-12T14:30:00Z',
    recipient: 'Alice',
    honor: 'summa cum laude',
    detail: 'Outstanding performance',
    date: '2026-03-12',
    authority: 'Test Authority',
    payload_sha256: 'abcd1234'.repeat(8),
    signature_b64url: 'c2lnbmF0dXJl',
    ...overrides,
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  if (tmpDir) {
    await fs.rm(tmpDir, { recursive: true, force: true });
    tmpDir = undefined;
  }
});

describe('appendIssuanceRecord', () => {
  it('creates file with [record] when file does not exist', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const record = makeRecord();

    await appendIssuanceRecord(lp, record);

    const contents = JSON.parse(await fs.readFile(lp, 'utf-8'));
    expect(contents).toEqual([record]);
  });

  it('appends to existing file', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const first = makeRecord({ recipient: 'Alice' });
    const second = makeRecord({ recipient: 'Bob' });

    await fs.writeFile(lp, JSON.stringify([first], null, 2) + '\n', 'utf-8');
    await appendIssuanceRecord(lp, second);

    const contents = JSON.parse(await fs.readFile(lp, 'utf-8'));
    expect(contents).toEqual([first, second]);
  });

  it('preserves order across multiple sequential appends', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const records = ['A', 'B', 'C'].map((r) => makeRecord({ recipient: r }));

    for (const record of records) {
      await appendIssuanceRecord(lp, record);
    }

    const contents = JSON.parse(await fs.readFile(lp, 'utf-8'));
    expect(contents).toEqual(records);
    expect(contents.map((r: IssuanceRecord) => r.recipient)).toEqual([
      'A',
      'B',
      'C',
    ]);
  });

  it('leaves no tmp files after successful append (atomic write)', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);

    await appendIssuanceRecord(lp, makeRecord());

    const files = await fs.readdir(dir);
    const tmpFiles = files.filter((f) => f.includes('.tmp.'));
    expect(tmpFiles).toHaveLength(0);
    const contents = JSON.parse(await fs.readFile(lp, 'utf-8'));
    expect(contents).toHaveLength(1);
  });

  it('writes log file with 0o600 permissions (no group/other access)', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);

    await appendIssuanceRecord(lp, makeRecord());

    const stat = await fs.stat(lp);
    expect(stat.mode & 0o077).toBe(0);
  });

  it('propagates fs.rename failure to caller', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);

    const renameSpy = vi.spyOn(fs, 'rename').mockRejectedValueOnce(
      Object.assign(new Error('EEXIST: file already exists'), {
        code: 'EEXIST',
      }),
    );

    await expect(appendIssuanceRecord(lp, makeRecord())).rejects.toThrow(
      'EEXIST',
    );

    renameSpy.mockRestore();
  });

  // --- M7: Unpredictable tmp file path ---

  it('uses a random hex suffix for the tmp file path', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const openSpy = vi.spyOn(fs, 'open');

    await appendIssuanceRecord(lp, makeRecord());

    const openCall = openSpy.mock.calls.find(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('.tmp.'),
    );
    expect(openCall).toBeDefined();
    expect(openCall![0]).toMatch(/\.tmp\.[0-9a-f]{16}$/);

    openSpy.mockRestore();
  });

  it('generates different tmp paths on successive calls', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const openSpy = vi.spyOn(fs, 'open');

    await appendIssuanceRecord(lp, makeRecord({ recipient: 'First' }));
    await appendIssuanceRecord(lp, makeRecord({ recipient: 'Second' }));

    const tmpPaths = openSpy.mock.calls
      .filter((c) => typeof c[0] === 'string' && (c[0] as string).includes('.tmp.'))
      .map((c) => c[0] as string);

    expect(tmpPaths).toHaveLength(2);
    expect(tmpPaths[0]).not.toBe(tmpPaths[1]);

    openSpy.mockRestore();
  });

  it('does not pre-unlink the tmp file (relies on wx flag)', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const unlinkSpy = vi.spyOn(fs, 'unlink');

    await appendIssuanceRecord(lp, makeRecord());

    // With random tmp paths, no pre-cleanup unlink should occur
    expect(unlinkSpy).not.toHaveBeenCalled();

    unlinkSpy.mockRestore();
  });

  it('cleans up orphaned tmp file when writeFile throws', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);

    // Mock fs.open to return an fd whose writeFile throws.
    const mockFd = {
      writeFile: vi.fn().mockRejectedValue(new Error('ENOSPC: disk full')),
      close: vi.fn().mockResolvedValue(undefined),
    };
    const openSpy = vi.spyOn(fs, 'open').mockResolvedValue(mockFd as unknown as Awaited<ReturnType<typeof fs.open>>);
    const unlinkSpy = vi.spyOn(fs, 'unlink').mockResolvedValue(undefined);

    await expect(appendIssuanceRecord(lp, makeRecord())).rejects.toThrow('ENOSPC');

    // Verify the orphaned tmp file was cleaned up.
    expect(unlinkSpy).toHaveBeenCalledTimes(1);
    expect(unlinkSpy.mock.calls[0][0]).toMatch(/\.tmp\.[0-9a-f]{16}$/);

    // Verify fd was closed.
    expect(mockFd.close).toHaveBeenCalled();

    openSpy.mockRestore();
    unlinkSpy.mockRestore();
  });
});

describe('readIssuanceLog', () => {
  it('returns [] for non-existent file', async () => {
    const dir = await makeTmpDir();
    const result = await readIssuanceLog(path.join(dir, 'nope.json'));
    expect(result).toEqual([]);
  });

  it('returns parsed records from existing file', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const records = [makeRecord({ recipient: 'X' }), makeRecord({ recipient: 'Y' })];
    await fs.writeFile(lp, JSON.stringify(records, null, 2), 'utf-8');

    const result = await readIssuanceLog(lp);
    expect(result).toEqual(records);
  });

  it('throws descriptive error when log contains valid JSON that is not an array', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    await fs.writeFile(lp, '{}', 'utf-8');

    await expect(readIssuanceLog(lp)).rejects.toThrow(
      /expected array/,
    );
  });

  it('throws descriptive error when log contains a JSON string instead of array', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    await fs.writeFile(lp, '"just a string"', 'utf-8');

    await expect(readIssuanceLog(lp)).rejects.toThrow(
      /expected array/,
    );
  });

  it('throws descriptive error for corrupted JSON', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    await fs.writeFile(lp, '{ not valid json !!!', 'utf-8');

    await expect(readIssuanceLog(lp)).rejects.toThrow(
      /invalid JSON.*cannot be parsed/,
    );
  });

  it('serializes record fields correctly (timestamp, hash, signature)', async () => {
    const dir = await makeTmpDir();
    const lp = logPath(dir);
    const record = makeRecord({
      timestamp: '2026-03-12T14:30:00Z',
      payload_sha256: 'deadbeef'.repeat(8),
      signature_b64url: 'dGVzdHNpZw',
    });

    await appendIssuanceRecord(lp, record);
    const [result] = await readIssuanceLog(lp);

    expect(result.timestamp).toBe('2026-03-12T14:30:00Z');
    expect(result.payload_sha256).toBe('deadbeef'.repeat(8));
    expect(result.signature_b64url).toBe('dGVzdHNpZw');
  });

  it('sanitizes control characters in logPath error messages', async () => {
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'test-\x1b[31m-evil.json');
    await fs.writeFile(lp, '{ not valid }', 'utf-8');
    try {
      await readIssuanceLog(lp);
      expect.fail('should have thrown');
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/invalid JSON/);
      expect(msg).not.toMatch(/\x1b/);
    }
  });

  it('sanitizes control characters in logPath for non-array JSON', async () => {
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'test-\x1b[31m-evil.json');
    await fs.writeFile(lp, '{}', 'utf-8');
    try {
      await readIssuanceLog(lp);
      expect.fail('should have thrown');
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/expected array/);
      expect(msg).not.toMatch(/\x1b/);
    }
  });

  it('sanitizes bidi override characters in logPath error messages', async () => {
    const dir = await makeTmpDir();
    const lp = path.join(dir, 'test-\u202E\u200F-evil.json');
    await fs.writeFile(lp, '{ not valid }', 'utf-8');
    try {
      await readIssuanceLog(lp);
      expect.fail('should have thrown');
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toMatch(/\u202E/);
      expect(msg).not.toMatch(/\u200F/);
    }
  });
});
