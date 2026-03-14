import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sanitizeForError } from '../credential.js';
import { startServer } from './main.js';

function printUsage(): void {
  console.error(`Usage: rhg-server [options]

Options:
  --port <number>        Port to listen on (env: RHG_PORT, default: 3141)
  --token-file <path>    Write bearer token to file instead of stderr
  --help                 Show this help message`);
}

function parsePort(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`Invalid port: ${value} (must be 1-65535)`);
  }
  return n;
}

export function parseArgs(args: string[]): { port?: number; tokenFile?: string; help: boolean } {
  let port: number | undefined;
  let tokenFile: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help') {
      return { help: true };
    }

    if (arg === '--port') {
      const value = args[++i];
      if (value === undefined) {
        throw new Error('--port requires a value');
      }
      port = parsePort(value);
      continue;
    }

    if (arg === '--token-file') {
      const value = args[++i];
      if (value === undefined) {
        throw new Error('--token-file requires a value');
      }
      tokenFile = value;
      continue;
    }

    throw new Error(`Unknown flag: ${sanitizeForError(arg)}`);
  }

  return { port, tokenFile, help: false };
}

export async function main(): Promise<void> {
  let parsed: { port?: number; tokenFile?: string; help: boolean };
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (err: unknown) {
    console.error((err as Error).message);
    process.exit(1);
  }

  if (parsed.help) {
    printUsage();
    process.exit(0);
  }

  let port = parsed.port;

  if (port === undefined && process.env['RHG_PORT'] !== undefined) {
    port = parsePort(process.env['RHG_PORT']);
  }

  // Resolve relative to the package root (via import.meta.url), not process.cwd().
  // Path assumption: cli.ts compiles to dist/server/cli.js.
  // ../../issuer → <project-root>/issuer/
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const issuerPath = path.resolve(__dirname, '../../issuer');
  const issuerDir = fs.existsSync(issuerPath) ? issuerPath : null;
  if (!issuerDir) {
    console.error('Warning: issuer directory not found. Run "npm run build:issuer" to build the issuer interface.');
  }

  const { close } = await startServer({
    config: {
      ...(port !== undefined ? { port } : {}),
      ...(issuerDir !== null ? { issuerDir } : {}),
    },
    ...(parsed.tokenFile !== undefined ? { tokenFilePath: parsed.tokenFile } : {}),
  });

  process.on('SIGTERM', () => {
    close();
    process.exit(0);
  });
  process.on('SIGINT', () => {
    close();
    process.exit(0);
  });
}

/* c8 ignore next 4 -- entry-point guard, tested via integration */
if (process.argv[1]?.endsWith('/cli.js')) {
  main().catch((err: unknown) => {
    console.error(`Fatal: ${(err as Error).message}`);
    process.exit(1);
  });
}
