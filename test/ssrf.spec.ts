import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { assertSafeUrl, safeFetch, UrlPolicyError } from "../src/security/index.js";
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

describe("assertSafeUrl / safeFetch — SSRF guard", () => {
  it("refuses the cloud metadata endpoint", async () => {
    await expect(
      assertSafeUrl("http://169.254.169.254/latest/meta-data/", testConfig())
    ).rejects.toThrow();
  });

  it("refuses private-range literal IPs", async () => {
    await expect(assertSafeUrl("http://10.0.0.5/", testConfig())).rejects.toThrow();
    await expect(assertSafeUrl("http://192.168.1.1/", testConfig())).rejects.toThrow();
  });

  it("refuses loopback", async () => {
    await expect(assertSafeUrl("http://127.0.0.1/", testConfig())).rejects.toThrow();
  });

  it("refuses IPv4-mapped IPv6 loopback", async () => {
    await expect(assertSafeUrl("http://[::ffff:127.0.0.1]/", testConfig())).rejects.toThrow();
  });

  it("refuses IPv6 loopback and ULA", async () => {
    await expect(assertSafeUrl("http://[::1]/", testConfig())).rejects.toThrow();
    await expect(assertSafeUrl("http://[fc00::1]/", testConfig())).rejects.toThrow();
  });

  it("refuses non-http(s) schemes", async () => {
    await expect(assertSafeUrl("file:///etc/passwd", testConfig())).rejects.toThrow(UrlPolicyError);
    await expect(assertSafeUrl("gopher://127.0.0.1/", testConfig())).rejects.toThrow(UrlPolicyError);
    await expect(assertSafeUrl("ftp://example.com/", testConfig())).rejects.toThrow(UrlPolicyError);
  });

  it("refuses URLs with embedded userinfo", async () => {
    await expect(assertSafeUrl("http://user:pass@example.com/", testConfig())).rejects.toThrow(
      UrlPolicyError
    );
  });

  it("refuses an invalid URL", async () => {
    await expect(assertSafeUrl("not a url", testConfig())).rejects.toThrow(UrlPolicyError);
  });

  describe("encoded-IP bypasses (rely on WHATWG URL host normalization)", () => {
    it("refuses dotless decimal (2130706433 === 127.0.0.1)", async () => {
      await expect(assertSafeUrl("http://2130706433/", testConfig())).rejects.toThrow();
    });

    it("refuses dotless hex (0x7f000001 === 127.0.0.1)", async () => {
      await expect(assertSafeUrl("http://0x7f000001/", testConfig())).rejects.toThrow();
    });

    it("refuses octal-encoded octets (0177.0.0.1 === 127.0.0.1)", async () => {
      await expect(assertSafeUrl("http://0177.0.0.1/", testConfig())).rejects.toThrow();
    });

    it("refuses hex-encoded octets (0x7f.0.0.1 === 127.0.0.1)", async () => {
      await expect(assertSafeUrl("http://0x7f.0.0.1/", testConfig())).rejects.toThrow();
    });
  });

  it("allows an explicitly-allowed loopback target to pass validation", async () => {
    // Hermetic: DNS-resolving a loopback literal needs no listener and no network.
    await expect(
      assertSafeUrl("http://127.0.0.1:65535/", testConfig({ allowLocal: true }))
    ).resolves.toBeInstanceOf(URL);
  });
});

describe("safeFetch — hermetic happy path (local fixture, ALLOW_LOCAL opt-in)", () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  it("fetches and returns content from an explicitly allowed local target", async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello from fixture");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    const result = await safeFetch(`http://127.0.0.1:${port}/`, testConfig({ allowLocal: true }));

    expect(result.status).toBe(200);
    expect(result.body.toString("utf-8")).toBe("hello from fixture");
    expect(result.truncated).toBe(false);
  });

  it("enforces max_bytes and marks the response truncated", async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("0123456789");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    const result = await safeFetch(
      `http://127.0.0.1:${port}/`,
      testConfig({ allowLocal: true, maxBytes: 5 })
    );

    expect(result.truncated).toBe(true);
    expect(result.body.byteLength).toBe(5);
    expect(result.body.toString("utf-8")).toBe("01234");
  });
});
