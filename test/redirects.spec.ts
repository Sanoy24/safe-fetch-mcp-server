import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, SafeFetchError, UrlPolicyError } from "../src/security/index.js";
import type { SafeFetchConfig } from "../src/config.js";

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: false,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    ...overrides
  };
}

describe("redirect handling — per-hop re-validation", () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  async function startServer(handler: http.RequestListener): Promise<number> {
    server = http.createServer(handler);
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return (server.address() as AddressInfo).port;
  }

  it("refuses a redirect to the cloud metadata endpoint (row 8, the canonical case)", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });

    // The entry point is an explicitly-trusted local target (ALLOW_LOCAL=true), but
    // metadata/link-local is never bypassable — see isAlwaysBlockedIp.
    await expect(
      safeFetch(`http://127.0.0.1:${port}/`, testConfig({ allowLocal: true }))
    ).rejects.toThrow(/metadata|link-local/i);
  });

  it("refuses a redirect to a disallowed scheme", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(302, { location: "file:///etc/passwd" });
      res.end();
    });

    await expect(
      safeFetch(`http://127.0.0.1:${port}/`, testConfig({ allowLocal: true }))
    ).rejects.toThrow(UrlPolicyError);
  });

  it("enforces the max-redirect limit", async () => {
    const port = await startServer((req, res) => {
      const hop = Number.parseInt(req.url?.replace("/", "") ?? "0", 10) || 0;
      res.writeHead(302, { location: `/${hop + 1}` });
      res.end();
    });

    await expect(
      safeFetch(`http://127.0.0.1:${port}/0`, testConfig({ allowLocal: true, maxRedirects: 2 }))
    ).rejects.toThrow(SafeFetchError);
  });

  it("follows a redirect within the limit and returns the final content", async () => {
    const port = await startServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/end" });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("final destination");
    });

    const result = await safeFetch(
      `http://127.0.0.1:${port}/start`,
      testConfig({ allowLocal: true, maxRedirects: 2 })
    );

    expect(result.status).toBe(200);
    expect(result.body.toString("utf-8")).toBe("final destination");
    expect(result.finalUrl).toBe(`http://127.0.0.1:${port}/end`);
  });

  it("re-validates on every call — no first-call-only guard bypass (poller regression)", async () => {
    // The real 2026 CVE: a guard applied on first load but skipped by a recurring
    // re-fetch/poller path. There is only one fetch path here (fetchWithRedirects),
    // so nothing should differ between the 1st and 3rd call against a blocked target.
    const cfg = testConfig();
    await expect(safeFetch("http://127.0.0.1:1/", cfg)).rejects.toThrow();
    await expect(safeFetch("http://127.0.0.1:1/", cfg)).rejects.toThrow();
    await expect(safeFetch("http://127.0.0.1:1/", cfg)).rejects.toThrow();
  });
});
