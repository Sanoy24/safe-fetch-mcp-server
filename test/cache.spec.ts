import { describe, it, expect, afterEach, beforeEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, ResolutionError } from "../src/security/index.js";
import { clearResponseCache } from "../src/security/responseCache.js";
import type { Resolver } from "../src/security/resolveAndPin.js";
import type { SafeFetchConfig } from "../src/config.js";

// Phase 5 response cache: opt-in, bounded, and never a way around the guard.

const TTL_MS = 60_000;

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    cache: { ttlMs: TTL_MS, maxEntries: 100, maxBytes: 1_000_000 },
    ...overrides
  };
}

interface Hit {
  readonly path: string;
  readonly ifNoneMatch: string | undefined;
}

let server: http.Server | undefined;
let hits: Hit[] = [];
let clock = 0;
const now = (): number => clock;

beforeEach(() => {
  clearResponseCache();
  hits = [];
  clock = 1_000_000;
});

afterEach(async () => {
  if (!server) return;
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<string> {
  server = http.createServer((req, res) => {
    const inm = req.headers["if-none-match"];
    hits.push({ path: req.url ?? "", ifNoneMatch: Array.isArray(inm) ? inm[0] : inm });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function text(res: http.ServerResponse, body: string, headers = {}): void {
  res.writeHead(200, { "content-type": "text/plain", ...headers });
  res.end(body);
}

describe("response cache", () => {
  it("is disabled by default", async () => {
    const base = await serve((_req, res) => text(res, "hello"));
    const cfg = testConfig({ cache: undefined });

    await safeFetch(`${base}/`, cfg, { now });
    const second = await safeFetch(`${base}/`, cfg, { now });

    expect(hits).toHaveLength(2);
    expect(second.fromCache).toBeFalsy();
  });

  it("serves a fresh repeat request from memory", async () => {
    const base = await serve((_req, res) => text(res, "hello"));

    await safeFetch(`${base}/`, testConfig(), { now });
    const second = await safeFetch(`${base}/`, testConfig(), { now });

    expect(hits).toHaveLength(1);
    expect(second.fromCache).toBe(true);
    expect(second.body.toString()).toBe("hello");
  });

  it("re-runs the full guard on a hit: a stricter policy refuses cached content", async () => {
    const base = await serve((_req, res) => text(res, "internal"));

    await safeFetch(`${base}/`, testConfig({ allowLocal: true }), { now });

    await expect(
      safeFetch(`${base}/`, testConfig({ allowLocal: false }), { now })
    ).rejects.toThrow(ResolutionError);
    expect(hits).toHaveLength(1);
  });

  it("re-checks DNS on a hit: a host that now resolves somewhere forbidden is refused", async () => {
    const base = await serve((_req, res) => text(res, "hello"));
    const port = new URL(base).port;
    let answer = "127.0.0.1";
    const resolver: Resolver = async () => [{ address: answer, family: 4 }];

    await safeFetch(`http://cache.test:${port}/`, testConfig(), {
      now,
      resolve: resolver
    });
    answer = "169.254.169.254";

    await expect(
      safeFetch(`http://cache.test:${port}/`, testConfig(), { now, resolve: resolver })
    ).rejects.toThrow(ResolutionError);
  });

  it("does not store responses marked no-store or private", async () => {
    const base = await serve((req, res) =>
      text(res, "x", { "cache-control": req.url === "/a" ? "no-store" : "private" })
    );

    for (const path of ["/a", "/a", "/b", "/b"]) {
      await safeFetch(`${base}${path}`, testConfig(), { now });
    }

    expect(hits).toHaveLength(4);
  });

  it("honours a max-age shorter than the configured TTL", async () => {
    const base = await serve((_req, res) =>
      text(res, "x", { "cache-control": "max-age=10" })
    );

    await safeFetch(`${base}/`, testConfig(), { now });
    clock += 5_000;
    await safeFetch(`${base}/`, testConfig(), { now });
    clock += 6_000; // 11 s old: past max-age, still inside the 60 s TTL
    await safeFetch(`${base}/`, testConfig(), { now });

    expect(hits).toHaveLength(2);
  });

  it("revalidates a stale entry with If-None-Match and reuses the body on 304", async () => {
    const base = await serve((req, res) => {
      if (req.headers["if-none-match"] === '"v1"') {
        res.writeHead(304, { etag: '"v1"' });
        res.end();
        return;
      }
      text(res, "body-v1", { etag: '"v1"' });
    });

    await safeFetch(`${base}/`, testConfig(), { now });
    clock += TTL_MS + 1;
    const revalidated = await safeFetch(`${base}/`, testConfig(), { now });

    expect(hits.map((h) => h.ifNoneMatch)).toEqual([undefined, '"v1"']);
    expect(revalidated.status).toBe(200);
    expect(revalidated.body.toString()).toBe("body-v1");
    expect(revalidated.fromCache).toBe(true);
  });

  it("sends validators only on the hop that produced them, not earlier redirect hops", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/final" });
        res.end();
        return;
      }
      text(res, "final", { etag: '"f1"' });
    });

    await safeFetch(`${base}/start`, testConfig(), { now });
    clock += TTL_MS + 1;
    await safeFetch(`${base}/start`, testConfig(), { now });

    expect(hits.slice(2)).toEqual([
      { path: "/start", ifNoneMatch: undefined },
      { path: "/final", ifNoneMatch: '"f1"' }
    ]);
  });

  it("evicts least-recently-used entries beyond maxEntries", async () => {
    const base = await serve((req, res) => text(res, req.url ?? ""));
    const cfg = testConfig({
      cache: { ttlMs: TTL_MS, maxEntries: 2, maxBytes: 1_000_000 }
    });

    for (const path of ["/1", "/2", "/1", "/3", "/1", "/2"]) {
      await safeFetch(`${base}${path}`, cfg, { now });
    }

    // /1 stays hot; /2 is evicted by /3 and must be fetched again.
    expect(hits.map((h) => h.path)).toEqual(["/1", "/2", "/3", "/2"]);
  });

  it("keeps total cached bytes under the configured bound", async () => {
    const base = await serve((_req, res) => text(res, "x".repeat(600)));
    const cfg = testConfig({
      cache: { ttlMs: TTL_MS, maxEntries: 100, maxBytes: 1_000 }
    });

    for (const path of ["/a", "/b", "/a"]) {
      await safeFetch(`${base}${path}`, cfg, { now });
    }

    // Two 600-byte bodies don't fit in 1000 bytes, so /a was evicted by /b.
    expect(hits.map((h) => h.path)).toEqual(["/a", "/b", "/a"]);
  });

  it("keys entries by byte limit, so a smaller cap never returns a larger cached body", async () => {
    const base = await serve((_req, res) => text(res, "0123456789"));

    await safeFetch(`${base}/`, testConfig(), { now });
    const capped = await safeFetch(`${base}/`, testConfig({ maxBytes: 4 }), { now });

    expect(capped.body.toString()).toBe("0123");
    expect(capped.truncated).toBe(true);
  });

  it("does not cache error statuses", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("missing");
    });

    await safeFetch(`${base}/`, testConfig(), { now });
    await safeFetch(`${base}/`, testConfig(), { now });

    expect(hits).toHaveLength(2);
  });
});
