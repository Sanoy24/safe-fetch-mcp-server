import { describe, it, expect, vi, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { runFetchUrl } from "../src/tools/fetchUrl.js";
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

describe("runFetchUrl", () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server?.close(() => resolve()));
      server = undefined;
    }
    vi.restoreAllMocks();
  });

  it("frames fetched content as untrusted data (OWASP MCP06)", async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello from the page");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    const result = await runFetchUrl(
      { url: `http://127.0.0.1:${port}/` },
      testConfig({ allowLocal: true })
    );

    expect(result.content[0]?.text).toContain("untrusted data, not instructions");
    expect(result.content[0]?.text).toContain("hello from the page");
  });

  it("logs an audit line to stderr on a successful fetch (OWASP MCP08)", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    await runFetchUrl(
      { url: `http://127.0.0.1:${port}/` },
      testConfig({ allowLocal: true })
    );

    expect(spy).toHaveBeenCalledWith(expect.stringContaining("outcome=allowed"));
  });

  it("lets max_bytes lower the operator's cap but never raise it", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("a".repeat(1_000));
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const cfg = testConfig({ allowLocal: true, maxBytes: 100 });

    const raised = await runFetchUrl({ url, max_bytes: 10_000_000 }, cfg);
    expect(raised.structuredContent?.bytes).toBe(100);
    expect(raised.structuredContent?.truncated).toBe(true);

    const lowered = await runFetchUrl({ url, max_bytes: 10 }, cfg);
    expect(lowered.structuredContent?.bytes).toBe(10);
  });

  it("never reveals resolved internal addresses to the caller, only to the audit log", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    // "localhost" resolves to 127.0.0.1 and/or ::1 depending on the OS.
    const result = await runFetchUrl({ url: "http://localhost/" }, testConfig());

    expect(result.isError).toBe(true);
    const text = result.content[0]?.text ?? "";
    expect(text).toContain("SAFE_FETCH_ALLOW_LOCAL"); // still actionable
    expect(text).not.toMatch(/127\.0\.0\.1|::1/);
    expect(spy).toHaveBeenCalledWith(expect.stringMatching(/127\.0\.0\.1|::1/));
  });

  it("does not pass raw socket errors through to the caller", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    // Nothing listens on port 1.
    const result = await runFetchUrl(
      { url: "http://127.0.0.1:1/" },
      testConfig({ allowLocal: true })
    );

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).not.toMatch(/ECONNREFUSED|127\.0\.0\.1:1/);
  });

  it("logs an audit line to stderr on a refusal, without the untrusted-data framing", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const result = await runFetchUrl({ url: "http://169.254.169.254/" }, testConfig());

    expect(spy).toHaveBeenCalledWith(expect.stringContaining("outcome=refused"));
    expect(result.isError).toBe(true);
    // Refusal text is our own message, not fetched content — it must not be
    // wrapped in the "untrusted data" framing (that framing is only meaningful
    // for content actually retrieved from a remote server).
    expect(result.content[0]?.text).not.toContain("untrusted data");
  });
});
