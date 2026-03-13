import { sanitizeForError } from '../credential.js';
import { startServer } from './main.js';

function printUsage(): void {
  console.error(`Usage: rhg-server [options]

Options:
  --port <number>   Port to listen on (env: RHG_PORT, default: 3141)
  --help            Show this help message`);
}

function parsePort(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error(`Invalid port: ${value} (must be 1-65535)`);
  }
  return n;
}

export function parseArgs(args: string[]): { port?: number; help: boolean } {
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
      return { port: parsePort(value), help: false };
    }

    throw new Error(`Unknown flag: ${sanitizeForError(arg)}`);
  }

  return { help: false };
}

export async function main(): Promise<void> {
  let parsed: { port?: number; help: boolean };
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

  const { close } = await startServer({
    config: port !== undefined ? { port } : undefined,
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
