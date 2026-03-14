import { describe, expect, it } from 'vitest';
import { parseArgs } from '../../server/cli.js';

describe('parseArgs', () => {
  it('returns { help: false } for empty args', () => {
    const result = parseArgs([]);
    expect(result).toEqual({ help: false });
  });

  it('returns { help: true } for --help', () => {
    const result = parseArgs(['--help']);
    expect(result).toEqual({ help: true });
  });

  it('returns { port: 3000, help: false } for --port 3000', () => {
    const result = parseArgs(['--port', '3000']);
    expect(result).toEqual({ port: 3000, help: false });
  });

  it('throws on unknown flag', () => {
    expect(() => parseArgs(['--unknown'])).toThrow(/Unknown flag/);
  });

  it('sanitizes control characters in unknown flag error message', () => {
    expect(() => parseArgs(['--foo\x1b[31m'])).toThrow();
    try {
      parseArgs(['--foo\x1b[31m']);
    } catch (e) {
      expect((e as Error).message).not.toMatch(/\x1b/);
    }
  });

  it('throws when --port has no value', () => {
    expect(() => parseArgs(['--port'])).toThrow('--port requires a value');
  });

  it('throws for invalid port number', () => {
    expect(() => parseArgs(['--port', '99999'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('throws for non-numeric port', () => {
    expect(() => parseArgs(['--port', 'abc'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('throws for port 0', () => {
    expect(() => parseArgs(['--port', '0'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('accepts port 1 (minimum)', () => {
    const result = parseArgs(['--port', '1']);
    expect(result).toEqual({ port: 1, help: false });
  });

  it('accepts port 65535 (maximum)', () => {
    const result = parseArgs(['--port', '65535']);
    expect(result).toEqual({ port: 65535, help: false });
  });

  it('throws for port 65536 (above maximum)', () => {
    expect(() => parseArgs(['--port', '65536'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('throws for fractional port', () => {
    expect(() => parseArgs(['--port', '3.14'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('throws for negative port', () => {
    expect(() => parseArgs(['--port', '-1'])).toThrow(
      /Invalid port.*must be 1-65535/,
    );
  });

  it('sanitizes bidi override characters in unknown flag error message', () => {
    try {
      parseArgs(['--test\u202E\u200F\u061C']);
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toMatch(/\u202E/);
      expect(msg).not.toMatch(/\u200F/);
      expect(msg).not.toMatch(/\u061C/);
    }
  });

  it('returns tokenFile for --token-file flag', () => {
    const result = parseArgs(['--token-file', '/tmp/tok']);
    expect(result).toEqual({ tokenFile: '/tmp/tok', help: false });
  });

  it('throws when --token-file has no value', () => {
    expect(() => parseArgs(['--token-file'])).toThrow('--token-file requires a value');
  });

  it('parses --port and --token-file together', () => {
    const result = parseArgs(['--port', '4000', '--token-file', '/tmp/tok']);
    expect(result).toEqual({ port: 4000, tokenFile: '/tmp/tok', help: false });
  });

  it('parses --token-file and --port in reverse order', () => {
    const result = parseArgs(['--token-file', '/tmp/tok', '--port', '4000']);
    expect(result).toEqual({ port: 4000, tokenFile: '/tmp/tok', help: false });
  });

  it('returns help: true for --help even with other flags before it', () => {
    const result = parseArgs(['--port', '4000', '--help']);
    expect(result).toEqual({ help: true });
  });
});
