import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { sanitizeForError } from '../credential.js';
import type { IssuanceRecord } from './types.js';

/**
 * Append an issuance record to a JSON log file using atomic write.
 * Creates the file with `[record]` if it does not exist.
 * Writes to a `.tmp.<random>` sibling then renames for crash safety on POSIX.
 * Callers are responsible for serialization (no concurrent calls).
 */
export async function appendIssuanceRecord(
  logPath: string,
  record: IssuanceRecord,
): Promise<void> {
  const records = await readIssuanceLog(logPath);
  records.push(record);
  const tmpPath = logPath + '.tmp.' + crypto.randomBytes(8).toString('hex');
  const fd = await fs.open(tmpPath, 'wx', 0o600);
  let writeOk = false;
  try {
    await fd.writeFile(JSON.stringify(records, null, 2) + '\n', 'utf-8');
    writeOk = true;
  } finally {
    await fd.close();
    if (!writeOk) {
      await fs.unlink(tmpPath).catch(() => {});
    }
  }
  // Windows: fs.rename over existing file may throw EEXIST; acceptable for single-user localhost tool
  await fs.rename(tmpPath, logPath);
}

/**
 * Read and parse the issuance log at `logPath`.
 * Returns `[]` if the file does not exist.
 * Throws a descriptive error if the file exists but contains invalid JSON.
 */
export async function readIssuanceLog(
  logPath: string,
): Promise<IssuanceRecord[]> {
  let raw: string;
  try {
    raw = await fs.readFile(logPath, 'utf-8');
  } catch (err: unknown) {
    if (isNodeError(err) && err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `Issuance log at ${sanitizeForError(logPath)} contains invalid JSON and cannot be parsed`,
    );
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`Issuance log at ${sanitizeForError(logPath)} contains invalid JSON: expected array`);
  }
  return parsed as IssuanceRecord[];
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}
