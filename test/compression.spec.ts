import { describe, it, expect, afterEach, beforeAll } from "vitest";
import * as http from "node:http";
import * as zlib from "node:zlib";
import type { AddressInfo } from "node:net";
import { safeFetch, GuardError } from "../src/security/index.js";
import type { SafeFetchConfig } from "../src/config.js";

// Compressed responses (threat-model row 23): we ask for gzip/br/deflate to save
// bandwidth, decompress while streaming, and enforce the byte cap on the DECOMPRESSED
// size, so a decompression bomb stops at the cap instead of exhausting memory.

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 1_000_000,
    timeoutMs: 5_000,
    maxRedirects: 5,
    ...overrides
  };
}

const TEXT = "safe-fetch compression test. ".repeat(200);
let bomb: Buffer; // ~50 MB of zeros, gzipped to ~50 KB

beforeAll(() => {
  bomb = zlib.gzipSync(Buffer.alloc(50 * 1024 * 1024), { level: 9 });
});

let server: http.Server | undefined;
let lastAcceptEncoding: string | undefined;

async function serve(encoding: string | undefined, body: Buffer): Promise<string> {
  server = http.createServer((req, res) => {
    lastAcceptEncoding = req.headers["accept-encoding"];
    res.writeHead(200, {
      "content-type": "text/plain",
      ...(encoding ? { "content-encoding": encoding } : {})
    });
    res.end(body);
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
}

afterEach(async () => {
  if (!server) return;
  server.closeAllConnections();
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  return promise.then(
    () => undefined,
    (e: unknown) => (e instanceof GuardError ? e.code : `non-guard: ${String(e)}`)
  );
}

describe("compressed responses", () => {
  it("advertises gzip, br and deflate", async () => {
    const url = await serve(undefined, Buffer.from("plain"));
    await safeFetch(url, testConfig());
    expect(lastAcceptEncoding).toBe("gzip, br, deflate");
  });

  it.each([
    ["gzip", zlib.gzipSync(TEXT)],
    ["x-gzip", zlib.gzipSync(TEXT)],
    ["br", zlib.brotliCompressSync(TEXT)],
    ["deflate", zlib.deflateSync(TEXT)],
    ["deflate (raw, no zlib header)", zlib.deflateRawSync(TEXT)]
  ] as const)("decodes %s", async (label, body) => {
    const url = await serve(label.startsWith("deflate") ? "deflate" : label, body);

    const result = await safeFetch(url, testConfig());

    expect(result.body.toString("utf-8")).toBe(TEXT);
    expect(result.truncated).toBe(false);
  });

  it("stops a gzip bomb at the byte cap, measured after decompression", async () => {
    const url = await serve("gzip", bomb);
    const started = Date.now();

    const result = await safeFetch(url, testConfig({ maxBytes: 100_000 }));

    expect(result.truncated).toBe(true);
    expect(result.body.byteLength).toBe(100_000);
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("stops a brotli bomb at the byte cap", async () => {
    const brBomb = zlib.brotliCompressSync(Buffer.alloc(20 * 1024 * 1024));
    const url = await serve("br", brBomb);

    const result = await safeFetch(url, testConfig({ maxBytes: 50_000 }));

    expect(result.truncated).toBe(true);
    expect(result.body.byteLength).toBe(50_000);
  });

  it("refuses a corrupt compressed body with INVALID_RESPONSE", async () => {
    const corrupt = Buffer.concat([
      zlib.gzipSync(TEXT).subarray(0, 20),
      Buffer.from("garbage")
    ]);
    const url = await serve("gzip", corrupt);

    expect(await codeOf(safeFetch(url, testConfig()))).toBe("INVALID_RESPONSE");
  });

  it("refuses an encoding we never asked for with INVALID_RESPONSE", async () => {
    const url = await serve("compress", Buffer.from("whatever"));

    expect(await codeOf(safeFetch(url, testConfig()))).toBe("INVALID_RESPONSE");
  });

  it("treats identity and an absent encoding as uncompressed", async () => {
    const url = await serve("identity", Buffer.from("plain body"));

    const result = await safeFetch(url, testConfig());

    expect(result.body.toString("utf-8")).toBe("plain body");
  });
});
