import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { runFetchUrl, FetchUrlOutput, DEFAULT_MAX_CHARS } from "../src/tools/fetchUrl.js";
import type { SafeFetchConfig } from "../src/config.js";

// The fetch_url result contract: stable, machine-readable error codes and
// structuredContent that always conforms to the declared outputSchema.

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 1_000,
    maxRedirects: 2,
    ...overrides
  };
}

let server: http.Server | undefined;

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (!server) return;
  server.closeAllConnections();
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

async function serve(handler: http.RequestListener): Promise<string> {
  server = http.createServer(handler);
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("error codes", () => {
  async function errorOf(
    args: unknown,
    cfg: SafeFetchConfig = testConfig()
  ): Promise<{ code: unknown; retryable: unknown }> {
    const result = await runFetchUrl(args, cfg);
    expect(result.isError).toBe(true);
    expect(FetchUrlOutput.safeParse(result.structuredContent).success).toBe(true);
    const error = result.structuredContent?.error;
    return { code: error?.code, retryable: error?.retryable };
  }

  it("INVALID_INPUT for schema violations", async () => {
    expect(await errorOf({ url: "not a url" })).toEqual({
      code: "INVALID_INPUT",
      retryable: false
    });
    expect(await errorOf({ url: "https://example.com", extra: 1 })).toEqual({
      code: "INVALID_INPUT",
      retryable: false
    });
  });

  it("POLICY_REJECTED for scheme, userinfo, allowlist and blocked addresses", async () => {
    const rejected = { code: "POLICY_REJECTED", retryable: false };
    expect(await errorOf({ url: "file:///etc/passwd" })).toEqual(rejected);
    expect(await errorOf({ url: "http://u:p@example.com/" })).toEqual(rejected);
    expect(
      await errorOf(
        { url: "http://127.0.0.1/" },
        testConfig({ allowlist: ["example.com"] })
      )
    ).toEqual(rejected);
    expect(await errorOf({ url: "http://169.254.169.254/" })).toEqual(rejected);
    expect(
      await errorOf({ url: "http://127.0.0.1/" }, testConfig({ allowLocal: false }))
    ).toEqual(rejected);
  });

  it("DNS_RESOLUTION_FAILED (retryable) for an unresolvable host", async () => {
    expect(await errorOf({ url: "http://does-not-exist.invalid/" })).toEqual({
      code: "DNS_RESOLUTION_FAILED",
      retryable: true
    });
  });

  it("CONNECTION_FAILED (retryable) when nothing is listening", async () => {
    expect(await errorOf({ url: "http://127.0.0.1:1/" })).toEqual({
      code: "CONNECTION_FAILED",
      retryable: true
    });
  });

  it("TIMEOUT (retryable) when the deadline passes", async () => {
    const base = await serve(() => undefined); // never responds
    expect(await errorOf({ url: `${base}/` }, testConfig({ timeoutMs: 200 }))).toEqual({
      code: "TIMEOUT",
      retryable: true
    });
  });

  it("REDIRECT_FAILED for too many redirects or a missing Location", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/no-location") {
        res.writeHead(302);
        res.end();
        return;
      }
      res.writeHead(302, { location: "/loop" });
      res.end();
    });
    const failed = { code: "REDIRECT_FAILED", retryable: false };
    expect(await errorOf({ url: `${base}/loop` })).toEqual(failed);
    expect(await errorOf({ url: `${base}/no-location` })).toEqual(failed);
  });

  it("a redirect to a blocked address is POLICY_REJECTED, not REDIRECT_FAILED", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/" });
      res.end();
    });
    expect((await errorOf({ url: `${base}/` })).code).toBe("POLICY_REJECTED");
  });
});

describe("successful results", () => {
  it("conform to the declared outputSchema", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hello");
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.isError).toBeUndefined();
    expect(FetchUrlOutput.strict().safeParse(result.structuredContent).success).toBe(
      true
    );
    expect(result.structuredContent?.error).toBeUndefined();
  });
});

describe("paging with max_chars / start_index", () => {
  async function page(args: Record<string, unknown>): ReturnType<typeof runFetchUrl> {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("0123456789".repeat(5)); // 50 chars
    });
    return runFetchUrl({ url: `${base}/`, ...args }, testConfig());
  }

  it("returns at most max_chars and points at the next chunk", async () => {
    const result = await page({ max_chars: 20 });

    expect(result.structuredContent).toMatchObject({
      totalChars: 50,
      startIndex: 0,
      nextStartIndex: 20
    });
    const text = result.content[0]?.text ?? "";
    expect(text).toContain("01234567890123456789");
    expect(text).not.toContain("012345678901234567890");
    expect(text).toContain("start_index=20");
  });

  it("reads the last chunk and reports nothing left", async () => {
    const result = await page({ max_chars: 20, start_index: 40 });

    expect(result.structuredContent).toMatchObject({
      startIndex: 40,
      nextStartIndex: null
    });
    expect(result.content[0]?.text).toContain("0123456789");
    expect(result.content[0]?.text).not.toContain("start_index=");
  });

  it("returns an empty chunk past the end instead of failing", async () => {
    const result = await page({ start_index: 999 });

    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      startIndex: 50,
      nextStartIndex: null
    });
  });

  it("caps output by default so one call can't flood the agent's context", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("a".repeat(DEFAULT_MAX_CHARS * 3));
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.structuredContent?.nextStartIndex).toBe(DEFAULT_MAX_CHARS);
  });
});

describe("content types and decoding", () => {
  it("refuses binary content instead of returning mojibake", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "image/png" });
      res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]));
    });

    for (const format of ["markdown", "raw"]) {
      const result = await runFetchUrl({ url: `${base}/`, format }, testConfig());
      expect(result.isError).toBe(true);
      expect(result.structuredContent?.error?.code).toBe("UNSUPPORTED_CONTENT_TYPE");
      expect(result.content[0]?.text).toContain("image/png");
    }
  });

  it("accepts structured-syntax text types such as RSS feeds", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/rss+xml" });
      res.end("<rss><channel><title>t</title></channel></rss>");
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.isError).toBeUndefined();
    expect(result.content[0]?.text).toContain("<title>t</title>");
  });

  it("decodes using the declared charset", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain; charset=iso-8859-1" });
      res.end(Buffer.from([0x63, 0x61, 0x66, 0xe9])); // "café" in Latin-1
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.content[0]?.text).toContain("café");
  });

  it("falls back to UTF-8 for an unknown charset", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain; charset=not-a-charset" });
      res.end("héllo");
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.content[0]?.text).toContain("héllo");
  });
});

describe("audit log", () => {
  it("redacts query values and fragments", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });

    await runFetchUrl({ url: `${base}/p?token=s3cret&q=1#frag` }, testConfig());

    const logged = spy.mock.calls.map((args) => String(args[0])).join("\n");
    expect(logged).toContain("token=REDACTED");
    expect(logged).not.toContain("s3cret");
    expect(logged).not.toContain("#frag");
  });
});
