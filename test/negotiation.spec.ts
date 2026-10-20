import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { runFetchUrl, FetchUrlOutput } from "../src/tools/fetchUrl.js";
import type { SafeFetchConfig } from "../src/config.js";

// Markdown content negotiation ("Markdown for Agents", Cloudflare 2026-02; also Vercel,
// HackMD): ask for text/markdown first, pass server-rendered markdown through untouched,
// and surface the site's x-markdown-tokens count. Sites without support are unaffected.

function testConfig(): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 1_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5
  };
}

const MARKDOWN =
  "# Guide\n\nUse `npm ci`.\n\n- one_two_three\n- [link](https://example.com)\n";

let server: http.Server | undefined;
let lastAccept: string | undefined;

async function serve(handler: http.RequestListener): Promise<string> {
  server = http.createServer((req, res) => {
    lastAccept = req.headers.accept;
    handler(req, res);
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  lastAccept = undefined;
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (!server) return;
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

describe("markdown content negotiation", () => {
  it("prefers text/markdown, then HTML, and still accepts anything", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });

    await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(lastAccept).toMatch(/^text\/markdown\b/);
    expect(lastAccept).toContain("text/html;q=");
    expect(lastAccept).toContain("*/*;q=");
  });

  it("passes server-rendered markdown through unchanged and reports its token count", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, {
        "content-type": "text/markdown; charset=utf-8",
        "x-markdown-tokens": "42"
      });
      res.end(MARKDOWN);
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    // Not re-escaped by an HTML converter (underscores and backticks intact).
    expect(result.content[0]?.text).toContain(MARKDOWN.trim());
    expect(result.structuredContent).toMatchObject({
      contentType: "text/markdown; charset=utf-8",
      markdownTokens: 42
    });
    expect(FetchUrlOutput.strict().safeParse(result.structuredContent).success).toBe(
      true
    );
  });

  it("ignores a malformed x-markdown-tokens header", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, {
        "content-type": "text/markdown",
        "x-markdown-tokens": "lots"
      });
      res.end(MARKDOWN);
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.structuredContent?.markdownTokens).toBeUndefined();
  });

  it("still converts HTML from sites that don't negotiate", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<h1>Guide</h1><p>Hello</p>");
    });

    const result = await runFetchUrl({ url: `${base}/` }, testConfig());

    expect(result.content[0]?.text).toContain("# Guide");
    expect(result.structuredContent?.markdownTokens).toBeUndefined();
  });
});
