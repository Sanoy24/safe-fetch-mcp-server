import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, SafeFetchError } from "../src/security/index.js";
import type { Resolver } from "../src/security/resolveAndPin.js";
import type { SafeFetchConfig } from "../src/config.js";

// Row 11 (resource exhaustion): SAFE_FETCH_TIMEOUT_MS is a TOTAL deadline across
// DNS, connect, headers and body for every hop — not a socket-idle timer that a
// server can reset forever by dripping one byte at a time.

const TIMEOUT_MS = 400;
// Generous upper bound so the suite isn't flaky on slow CI, but far below what an
// idle-only timer would allow for these fixtures.
const MAX_ELAPSED_MS = TIMEOUT_MS * 3;

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: TIMEOUT_MS,
    maxRedirects: 5,
    ...overrides
  };
}

async function expectTimeout(promise: Promise<unknown>): Promise<void> {
  const started = Date.now();
  await expect(promise).rejects.toThrow(SafeFetchError);
  await promise.catch((err: unknown) => {
    expect((err as Error).message).toMatch(/timed out/);
  });
  expect(Date.now() - started).toBeLessThan(MAX_ELAPSED_MS);
}

describe("total request deadline", () => {
  let server: http.Server | undefined;
  const timers: NodeJS.Timeout[] = [];

  afterEach(async () => {
    timers.splice(0).forEach((t) => clearInterval(t));
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  async function startServer(handler: http.RequestListener): Promise<number> {
    server = http.createServer(handler);
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return (server.address() as AddressInfo).port;
  }

  it("aborts a slow-drip body that keeps the socket busy (slow-loris)", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      timers.push(setInterval(() => res.write("x"), 50));
    });

    await expectTimeout(safeFetch(`http://127.0.0.1:${port}/`, testConfig()));
  });

  it("aborts when the server never sends response headers", async () => {
    const port = await startServer(() => {
      // Accept the request and never answer.
    });

    await expectTimeout(safeFetch(`http://127.0.0.1:${port}/`, testConfig()));
  });

  it("applies one deadline across all redirect hops, not one per hop", async () => {
    const hopDelayMs = TIMEOUT_MS / 2;
    let hops = 0;
    const port = await startServer((req, res) => {
      hops += 1;
      const n = Number(req.url?.slice(1) ?? "0");
      setTimeout(() => {
        res.writeHead(302, { location: `/${n + 1}` });
        res.end();
      }, hopDelayMs);
    });

    await expectTimeout(safeFetch(`http://127.0.0.1:${port}/0`, testConfig()));
    // Per-hop timers would have let all maxRedirects+1 hops run.
    expect(hops).toBeLessThanOrEqual(3);
  });

  it("aborts when DNS resolution never completes", async () => {
    const hangingResolver: Resolver = () => new Promise(() => undefined);

    await expectTimeout(
      safeFetch("http://slow-dns.test/", testConfig(), { resolve: hangingResolver })
    );
  });
});
