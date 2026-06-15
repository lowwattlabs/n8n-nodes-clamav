/**
 * clamd.ts
 * Low-level helpers for communicating with a clamd TCP socket (RFC-style protocol).
 *
 * All exported functions are pure async and do not depend on n8n internals,
 * making them straightforward to unit-test by mocking `net.Socket`.
 *
 * clamd protocol reference:
 *   - Commands are sent as null-terminated strings prefixed with 'z'
 *     (e.g., "zPING\0", "zSCAN /path\0", "zSTATS\0").
 *   - INSTREAM streams raw bytes: [uint32-BE chunk-size][chunk-data] … [uint32-BE 0]
 *   - PING reply: "PONG\0"
 *   - SCAN reply: "<path>: OK\0"  or  "<path>: <virus> FOUND\0"
 *   - INSTREAM reply: "stream: OK\0"  or  "stream: <virus> FOUND\0"
 *   - STATS reply: multi-line block terminated by "END\n"
 */

import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';

/** Default TCP connection + read timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Low-level socket helper
// ---------------------------------------------------------------------------

/**
 * Open a TCP connection to clamd, send `writeBuffers` sequentially,
 * and collect the response until the socket closes (or `endMarker` is found).
 *
 * @param host        clamd host
 * @param port        clamd TCP port
 * @param writeBuffers Ordered list of Buffers to write after connecting
 * @param endMarker   Optional string; if found in response the socket is closed early
 * @param timeoutMs   Connection + idle timeout in milliseconds
 */
export function rawClamdCommand(
  host: string,
  port: number,
  writeBuffers: Buffer[],
  endMarker?: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const socket = new net.Socket();
    let response = '';

    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => {
      for (const buf of writeBuffers) {
        socket.write(buf);
      }
    });

    socket.on('data', (chunk: Buffer) => {
      response += chunk.toString('utf8');
      if (endMarker && response.includes(endMarker)) {
        socket.destroy();
        resolve(response.trim());
      }
    });

    socket.on('end', () => {
      resolve(response.trim());
    });

    socket.on('close', () => {
      resolve(response.trim());
    });

    socket.on('timeout', () => {
      socket.destroy(new Error(`clamd connection timed out after ${timeoutMs}ms`));
    });

    socket.on('error', (err: Error) => {
      reject(err);
    });
  });
}

// ---------------------------------------------------------------------------
// High-level protocol commands
// ---------------------------------------------------------------------------

/**
 * Send PING to clamd. Returns true when clamd replies with "PONG".
 */
export async function ping(
  host: string,
  port: number,
  timeoutMs?: number,
): Promise<boolean> {
  const cmd = Buffer.from('zPING\0');
  const response = await rawClamdCommand(host, port, [cmd], undefined, timeoutMs);
  return response.replace(/\0/g, '').trim() === 'PONG';
}

/**
 * Send SCAN <filePath> to clamd.
 * The clamd process must be able to read the file at `filePath`.
 *
 * @returns Raw clamd response string, e.g. "/tmp/test.pdf: OK"
 */
export async function scanFile(
  host: string,
  port: number,
  filePath: string,
  timeoutMs?: number,
): Promise<string> {
  const cmd = Buffer.from(`zSCAN ${filePath}\0`);
  return rawClamdCommand(host, port, [cmd], undefined, timeoutMs);
}

/**
 * Send INSTREAM <data> to clamd.
 * Use this to scan in-memory bytes or base64-decoded content.
 *
 * Protocol:
 *   1. Send "zINSTREAM\0"
 *   2. Send [uint32-BE length][data]  (repeat for multiple chunks)
 *   3. Send [uint32-BE 0] to end the stream
 *
 * @param data  Raw bytes to scan
 * @returns     Raw clamd response string, e.g. "stream: OK"
 */
export async function instreamScan(
  host: string,
  port: number,
  data: Buffer,
  timeoutMs?: number,
): Promise<string> {
  const cmdBuf = Buffer.from('zINSTREAM\0');

  // Chunk header: 4-byte big-endian length of the data block
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);

  // Terminating zero-length chunk
  const endBuf = Buffer.alloc(4);
  endBuf.writeUInt32BE(0, 0);

  return rawClamdCommand(host, port, [cmdBuf, lenBuf, data, endBuf], undefined, timeoutMs);
}

/**
 * Send STATS to clamd and return the full stats block.
 * The response is a multi-line string terminated by "END".
 */
export async function getStats(
  host: string,
  port: number,
  timeoutMs?: number,
): Promise<string> {
  const cmd = Buffer.from('zSTATS\0');
  return rawClamdCommand(host, port, [cmd], 'END', timeoutMs);
}

// ---------------------------------------------------------------------------
// Result parsing
// ---------------------------------------------------------------------------

/** Parsed result of a SCAN or INSTREAM response. */
export interface ScanResult {
  /** The scanned path, or "stream" for INSTREAM results. */
  path: string;
  /** Scan verdict. */
  status: 'OK' | 'FOUND' | 'ERROR';
  /** Virus/threat name when status is "FOUND". */
  virus?: string;
  /** Error detail when status is "ERROR". */
  errorMessage?: string;
  /** Raw clamd response string. */
  raw: string;
}

/**
 * Parse a single-line clamd scan response into a structured ScanResult.
 *
 * Expected formats:
 *   "/path/to/file: OK"
 *   "/path/to/file: Eicar-Signature FOUND"
 *   "/path/to/file: lstat() failed. ERROR"
 *   "stream: OK"
 *   "stream: Eicar-Signature FOUND"
 */
export function parseScanResult(response: string): ScanResult {
  // Strip null bytes clamd may append
  const raw = response.replace(/\0/g, '').trim();

  const foundMatch = /^(.+):\s+(.+)\s+FOUND$/.exec(raw);
  if (foundMatch) {
    return { path: foundMatch[1].trim(), status: 'FOUND', virus: foundMatch[2].trim(), raw };
  }

  const errorMatch = /^(.+):\s+(.+)\s+ERROR$/.exec(raw);
  if (errorMatch) {
    return {
      path: errorMatch[1].trim(),
      status: 'ERROR',
      errorMessage: errorMatch[2].trim(),
      raw,
    };
  }

  const okMatch = /^(.+):\s+OK$/.exec(raw);
  if (okMatch) {
    return { path: okMatch[1].trim(), status: 'OK', raw };
  }

  // Fallback: treat unrecognised output as an error
  return { path: 'unknown', status: 'ERROR', errorMessage: raw, raw };
}

// ---------------------------------------------------------------------------
// Premium helpers
// ---------------------------------------------------------------------------

/** Result produced by batchScan for each file. */
export interface BatchScanEntry {
  file: string;
  result: ScanResult;
}

/**
 * Recursively collect file paths under `directory`.
 * Symlinks are ignored; directories are traversed up to `maxDepth` levels.
 */
export function collectFiles(directory: string, maxDepth: number = 10, _depth: number = 0): string[] {
  if (_depth > maxDepth) return [];
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isFile()) {
      files.push(fullPath);
    } else if (entry.isDirectory() && _depth < maxDepth) {
      files.push(...collectFiles(fullPath, maxDepth, _depth + 1));
    }
  }
  return files;
}

/**
 * Scan every file in `directory` (recursively) via clamd SCAN command.
 * Returns one BatchScanEntry per file.
 *
 * **Premium feature** — caller must verify a valid license key before invoking.
 */
export async function batchScan(
  host: string,
  port: number,
  directory: string,
  recursive: boolean = true,
  timeoutMs?: number,
): Promise<BatchScanEntry[]> {
  const files = recursive ? collectFiles(directory) : fs.readdirSync(directory, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.join(directory, e.name));

  const results: BatchScanEntry[] = [];
  for (const file of files) {
    const raw = await scanFile(host, port, file, timeoutMs);
    results.push({ file, result: parseScanResult(raw) });
  }
  return results;
}

/** A single event produced by the real-time directory monitor. */
export interface MonitorEvent {
  timestamp: string;
  file: string;
  changeType: string;
  result: ScanResult;
}

/**
 * Watch `directory` for file-system changes using Node's fs.watch API.
 * Each new or changed file is immediately scanned via clamd.
 * The monitor runs for `durationMs` milliseconds then resolves with all events collected.
 *
 * **Premium feature** — caller must verify a valid license key before invoking.
 *
 * @param directory  Directory to watch
 * @param durationMs How long to watch (milliseconds); defaults to 30 000
 */
export function monitorDirectory(
  host: string,
  port: number,
  directory: string,
  durationMs: number = 30_000,
  timeoutMs?: number,
): Promise<MonitorEvent[]> {
  return new Promise<MonitorEvent[]>((resolve, reject) => {
    const events: MonitorEvent[] = [];
    let watcher: fs.FSWatcher;

    const done = (): void => {
      try {
        watcher.close();
      } catch {
        // already closed
      }
      resolve(events);
    };

    const timer = setTimeout(done, durationMs);

    try {
      watcher = fs.watch(directory, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(directory, filename);
        scanFile(host, port, fullPath, timeoutMs)
          .then((raw) => {
            events.push({
              timestamp: new Date().toISOString(),
              file: fullPath,
              changeType: eventType,
              result: parseScanResult(raw),
            });
          })
          .catch((err: Error) => {
            events.push({
              timestamp: new Date().toISOString(),
              file: fullPath,
              changeType: eventType,
              result: { path: fullPath, status: 'ERROR', errorMessage: err.message, raw: err.message },
            });
          });
      });

      watcher.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    } catch (err) {
      clearTimeout(timer);
      reject(err);
    }
  });
}

// ---------------------------------------------------------------------------
// License verification
// ---------------------------------------------------------------------------

/**
 * Verify a premium license key against the LowWatt Labs license server.
 * Returns true when the server confirms the key is valid.
 *
 * On any network error the function returns false (fail-closed).
 */
export function verifyLicenseKey(licenseKey: string): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    if (!licenseKey || licenseKey.trim() === '') {
      resolve(false);
      return;
    }

    // Dynamically require https to keep the module testable with jest.mock
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const https = require('https') as typeof import('https');

    const params = new URLSearchParams({
      key: licenseKey.trim(),
      product: 'n8n-nodes-clamav',
    });

    const url = `https://license.lowwattlabs.com/v1/verify?${params.toString()}`;

    https
      .get(url, (res) => {
        let data = '';
        res.on('data', (chunk: string) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const json = JSON.parse(data) as { valid?: boolean };
            resolve(json.valid === true);
          } catch {
            resolve(false);
          }
        });
      })
      .on('error', () => {
        resolve(false);
      });
  });
}
