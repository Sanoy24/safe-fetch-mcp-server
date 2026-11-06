import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { GuardError, safeFetch } from "../src/security/index.js";
import type { Resolver } from "../src/security/resolveAndPin.js";
import { extractInWorker } from "../src/content/extractPool.js";
import { loadConfig, type SafeFetchConfig } from "../src/config.js";

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    ...overrides
  };
}

const toLocal: Resolver = async () => [{ address: "127.0.0.1", family: 4 }];

let server: http.Server | undefined;
let inFlight = 0;
let peak = 0;
const peakPerHost = new Map<string, number>();
const inFlightPerHost = new Map<string, number>();

afterEach(async () => {
  inFlight = 0;
  peak = 0;
  peakPerHost.clear();
  inFlightPerHost.clear();
  if (!server) return;
  server.closeAllConnections();
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

/** Records how many requests overlap, overall and per Host header. */
async function serve(delayMs: number): Promise<number> {
  server = http.createServer((req, res) => {
    const host = (req.headers.host ?? "").split(":")[0] ?? "";
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    inFlightPerHost.set(host, (inFlightPerHost.get(host) ?? 0) + 1);
    peakPerHost.set(
      host,
      Math.max(peakPerHost.get(host) ?? 0, inFlightPerHost.get(host) ?? 0)
    );
    setTimeout(() => {
      inFlight -= 1;
      inFlightPerHost.set(host, (inFlightPerHost.get(host) ?? 1) - 1);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    }, delayMs);
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

describe("outbound concurrency limits", () => {
  it("never exceeds the per-host limit, and completes every request", async () => {
    const port = await serve(30);
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        safeFetch(`http://one.test:${port}/${i}`, testConfig({ maxPerHost: 2 }), {
          resolve: toLocal
        })
      )
    );
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(peakPerHost.get("one.test")).toBe(2);
  });

  it("never exceeds the global limit across hosts", async () => {
    const port = await serve(30);
    await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        safeFetch(
          `http://host${i}.test:${port}/`,
          testConfig({ maxConcurrent: 3, maxPerHost: 3 }),
          { resolve: toLocal }
        )
      )
    );
    expect(peak).toBe(3);
  });

  it("doesn't let a busy host hold up another host", async () => {
    const port = await serve(200);
    const cfg = testConfig({ maxPerHost: 1, timeoutMs: 5_000 });
    const busy = Array.from({ length: 3 }, () =>
      safeFetch(`http://busy.test:${port}/`, cfg, { resolve: toLocal })
    );
    const started = Date.now();
    await safeFetch(`http://other.test:${port}/`, cfg, { resolve: toLocal });
    expect(Date.now() - started).toBeLessThan(500);
    await Promise.all(busy);
  });

  it("counts queue time against the deadline, and the queue recovers afterwards", async () => {
    const port = await serve(400);
    const cfg = testConfig({ maxPerHost: 1, timeoutMs: 600 });
    const results = await Promise.allSettled(
      Array.from({ length: 4 }, () =>
        safeFetch(`http://slow.test:${port}/`, cfg, { resolve: toLocal })
      )
    );
    const failures = results.filter(
      (r): r is PromiseRejectedResult => r.status === "rejected"
    );
    expect(failures.length).toBeGreaterThan(0);
    for (const failure of failures) {
      expect((failure.reason as GuardError).code).toBe("TIMEOUT");
    }

    // Timed-out waiters left no slot behind.
    const after = await safeFetch(
      `http://slow.test:${port}/`,
      testConfig({ maxPerHost: 1 }),
      { resolve: toLocal }
    );
    expect(after.status).toBe(200);
  });

  it("releases the slot when a request fails", async () => {
    const cfg = testConfig({ maxPerHost: 1 });
    // Nothing listens on port 1.
    await expect(safeFetch("http://127.0.0.1:1/", cfg)).rejects.toBeInstanceOf(
      GuardError
    );
    const port = await serve(0);
    const result = await safeFetch(`http://127.0.0.1:${port}/`, cfg);
    expect(result.status).toBe(200);
  });

  it("doesn't deadlock a redirect to the same host at a limit of one", async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/end" });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("done");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const cfg = testConfig({ maxPerHost: 1, maxConcurrent: 1, robots: "respect" });
    const result = await safeFetch(`http://127.0.0.1:${port}/start`, cfg);
    expect(result.body.toString()).toBe("done");
  });
});

describe("page conversion queue", () => {
  it("refuses work beyond the queue limit instead of holding every body in memory", async () => {
    const job = {
      body: new Uint8Array(Buffer.from("<p>hello</p>")),
      contentType: "text/html",
      mode: "full" as const
    };
    const results = await Promise.allSettled(
      Array.from({ length: 60 }, () => extractInWorker(job, 10_000))
    );
    const refused = results.filter(
      (r): r is PromiseRejectedResult => r.status === "rejected"
    );
    expect(refused.length).toBeGreaterThan(0);
    expect(refused.length).toBeLessThan(60);
    const first = refused[0]?.reason as GuardError;
    expect(first.code).toBe("PROCESSING_LIMIT");
    expect(first.message).toContain("busy");
  });
});

describe("configuration", () => {
  it("has defaults and validates its limits", () => {
    expect(loadConfig({}).maxConcurrent).toBe(16);
    expect(loadConfig({}).maxPerHost).toBe(4);
    expect(loadConfig({ SAFE_FETCH_MAX_PER_HOST: "2" }).maxPerHost).toBe(2);
    expect(() => loadConfig({ SAFE_FETCH_MAX_CONCURRENT: "0" })).toThrow(
      /SAFE_FETCH_MAX_CONCURRENT/
    );
    expect(() => loadConfig({ SAFE_FETCH_MAX_PER_HOST: "many" })).toThrow(
      /SAFE_FETCH_MAX_PER_HOST/
    );
  });
});
