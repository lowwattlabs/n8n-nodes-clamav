/**
 * __tests__/Clamav.test.ts
 *
 * Unit tests for the clamd helper functions in nodes/Clamav/clamd.ts.
 *
 * The net module is mocked so no live clamd daemon is required.
 * All tests verify protocol correctness and result parsing.
 */

import { EventEmitter } from 'events';

// ---------------------------------------------------------------------------
// Mock net.Socket
// ---------------------------------------------------------------------------

// We capture the last created MockSocket instance so tests can drive its events.
let lastSocket: MockSocket;

class MockSocket extends EventEmitter {
  connected = false;
  destroyed = false;
  written: Buffer[] = [];

  connect(port: number, host: string, cb: () => void): this {
    void port;
    void host;
    this.connected = true;
    setImmediate(cb);
    return this;
  }

  write(data: Buffer | string): boolean {
    const buf = typeof data === 'string' ? Buffer.from(data) : data;
    this.written.push(buf);
    return true;
  }

  setTimeout(_ms: number, _cb?: () => void): this {
    return this;
  }

  destroy(err?: Error): this {
    this.destroyed = true;
    if (err) setImmediate(() => this.emit('error', err));
    return this;
  }

  /** Helper: simulate clamd sending a response and closing. */
  respondWith(data: string): void {
    setImmediate(() => {
      this.emit('data', Buffer.from(data));
      this.emit('end');
    });
  }
}

jest.mock('net', () => ({
  Socket: jest.fn().mockImplementation(() => {
    lastSocket = new MockSocket();
    return lastSocket;
  }),
}));

// ---------------------------------------------------------------------------
// Import helpers AFTER mocking net
// ---------------------------------------------------------------------------

import {
  parseScanResult,
  ping,
  scanFile,
  instreamScan,
  getStats,
  collectFiles,
} from '../nodes/Clamav/clamd';

// ---------------------------------------------------------------------------
// parseScanResult (pure function — no socket needed)
// ---------------------------------------------------------------------------

describe('parseScanResult()', () => {
  test('parses OK response', () => {
    const result = parseScanResult('/tmp/clean.txt: OK');
    expect(result.status).toBe('OK');
    expect(result.path).toBe('/tmp/clean.txt');
    expect(result.virus).toBeUndefined();
  });

  test('parses FOUND response', () => {
    const result = parseScanResult('/tmp/evil.exe: Eicar-Test-Signature FOUND');
    expect(result.status).toBe('FOUND');
    expect(result.path).toBe('/tmp/evil.exe');
    expect(result.virus).toBe('Eicar-Test-Signature');
  });

  test('parses ERROR response', () => {
    const result = parseScanResult('/tmp/missing.bin: lstat() failed. ERROR');
    expect(result.status).toBe('ERROR');
    expect(result.path).toBe('/tmp/missing.bin');
    expect(result.errorMessage).toMatch(/lstat/);
  });

  test('parses stream OK response (INSTREAM)', () => {
    const result = parseScanResult('stream: OK');
    expect(result.status).toBe('OK');
    expect(result.path).toBe('stream');
  });

  test('parses stream FOUND response (INSTREAM)', () => {
    const result = parseScanResult('stream: Eicar-Test-Signature FOUND');
    expect(result.status).toBe('FOUND');
    expect(result.path).toBe('stream');
    expect(result.virus).toBe('Eicar-Test-Signature');
  });

  test('strips null bytes from response', () => {
    const result = parseScanResult('/tmp/clean.pdf: OK\0');
    expect(result.status).toBe('OK');
  });

  test('returns ERROR for unrecognised response', () => {
    const result = parseScanResult('some garbage output');
    expect(result.status).toBe('ERROR');
    expect(result.errorMessage).toBe('some garbage output');
  });
});

// ---------------------------------------------------------------------------
// ping()
// ---------------------------------------------------------------------------

describe('ping()', () => {
  test('returns true when clamd replies PONG', async () => {
    const promise = ping('localhost', 3310);
    lastSocket.respondWith('PONG\0');
    const alive = await promise;
    expect(alive).toBe(true);
  });

  test('returns false on unexpected response', async () => {
    const promise = ping('localhost', 3310);
    lastSocket.respondWith('SOMETHING_ELSE');
    const alive = await promise;
    expect(alive).toBe(false);
  });

  test('rejects on socket error', async () => {
    const promise = ping('localhost', 3310);
    setImmediate(() => lastSocket.emit('error', new Error('ECONNREFUSED')));
    await expect(promise).rejects.toThrow('ECONNREFUSED');
  });
});

// ---------------------------------------------------------------------------
// scanFile()
// ---------------------------------------------------------------------------

describe('scanFile()', () => {
  test('sends zSCAN command with correct path', async () => {
    const promise = scanFile('localhost', 3310, '/tmp/test.pdf');
    lastSocket.respondWith('/tmp/test.pdf: OK\0');
    const raw = await promise;
    expect(raw).toContain('/tmp/test.pdf');
    // Verify correct command was written
    const allWritten = Buffer.concat(lastSocket.written).toString();
    expect(allWritten).toContain('zSCAN /tmp/test.pdf\0');
  });

  test('returns raw FOUND response unchanged', async () => {
    const promise = scanFile('localhost', 3310, '/tmp/virus.exe');
    lastSocket.respondWith('/tmp/virus.exe: Eicar-Test-Signature FOUND\0');
    const raw = await promise;
    expect(raw).toContain('FOUND');
  });

  test('parseScanResult correctly processes scanFile output', async () => {
    const promise = scanFile('localhost', 3310, '/tmp/clean.txt');
    lastSocket.respondWith('/tmp/clean.txt: OK');
    const raw = await promise;
    const result = parseScanResult(raw);
    expect(result.status).toBe('OK');
    expect(result.path).toBe('/tmp/clean.txt');
  });
});

// ---------------------------------------------------------------------------
// instreamScan()
// ---------------------------------------------------------------------------

describe('instreamScan()', () => {
  test('sends zINSTREAM command with data and terminating zero chunk', async () => {
    const testData = Buffer.from('Hello, ClamAV!');
    const promise = instreamScan('localhost', 3310, testData);
    lastSocket.respondWith('stream: OK\0');
    await promise;

    const written = lastSocket.written;
    // First write: command
    expect(written[0].toString()).toBe('zINSTREAM\0');
    // Second write: 4-byte BE length
    expect(written[1].length).toBe(4);
    expect(written[1].readUInt32BE(0)).toBe(testData.length);
    // Third write: data
    expect(written[2].toString()).toBe('Hello, ClamAV!');
    // Fourth write: terminating zero-length chunk
    expect(written[3].length).toBe(4);
    expect(written[3].readUInt32BE(0)).toBe(0);
  });

  test('returns stream: OK for clean content', async () => {
    const promise = instreamScan('localhost', 3310, Buffer.from('clean content'));
    lastSocket.respondWith('stream: OK\0');
    const raw = await promise;
    const result = parseScanResult(raw);
    expect(result.status).toBe('OK');
  });

  test('returns FOUND for infected content', async () => {
    const eicarBase64 = Buffer.from(
      'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELU1FU1NB' +
      'R0UtU1RBTkRBUkQtQU5USVZJUlVTLVRFU1QhJEgrSCo=',
      'base64',
    );
    const promise = instreamScan('localhost', 3310, eicarBase64);
    lastSocket.respondWith('stream: Eicar-Test-Signature FOUND\0');
    const raw = await promise;
    const result = parseScanResult(raw);
    expect(result.status).toBe('FOUND');
    expect(result.virus).toBe('Eicar-Test-Signature');
  });
});

// ---------------------------------------------------------------------------
// getStats()
// ---------------------------------------------------------------------------

describe('getStats()', () => {
  const statsResponse = [
    'POOLS: 1',
    '',
    'STATE: VALID PRIMARY',
    'THREADS: live 1  idle 0 max 12 idle-timeout 30',
    'QUEUE: 0 items',
    '  0 items',
    '',
    'MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A pools 1 pools_used 1218.4k pools_total 1218.4k',
    'END',
    '',
  ].join('\n');

  test('sends zSTATS command', async () => {
    const promise = getStats('localhost', 3310);
    lastSocket.respondWith(statsResponse);
    await promise;
    const allWritten = Buffer.concat(lastSocket.written).toString();
    expect(allWritten).toBe('zSTATS\0');
  });

  test('returns raw stats block containing END marker', async () => {
    const promise = getStats('localhost', 3310);
    lastSocket.respondWith(statsResponse);
    const raw = await promise;
    expect(raw).toContain('STATE:');
    expect(raw).toContain('END');
  });
});

// ---------------------------------------------------------------------------
// collectFiles() — uses real fs (only runs paths that exist)
// ---------------------------------------------------------------------------

describe('collectFiles()', () => {
  test('returns an array', () => {
    // Use a path that definitely exists on any *nix system
    const files = collectFiles('/tmp');
    expect(Array.isArray(files)).toBe(true);
  });

  test('returns only files, not directories', () => {
    const files = collectFiles('/tmp');
    const fs = require('fs') as typeof import('fs');
    for (const f of files) {
      const stat = fs.statSync(f);
      expect(stat.isFile()).toBe(true);
    }
  });
});
