import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { extractInWorker } from "../src/content/extractPool.js";
import { htmlToMarkdown } from "../src/content/toMarkdown.js";
import { runFetchUrl } from "../src/tools/fetchUrl.js";
import { GuardError } from "../src/security/errors.js";
import type { SafeFetchConfig } from "../src/config.js";

// Threat-model row 26: page conversion happens after the network deadline, on
// attacker-controlled input. It must never block the server or run unbounded.

const PARAGRAPH =
  "<p>The quick brown fox jumps over the lazy dog while the server converts this page.</p>\n";
const flatPage = (bytes: number): string =>
  `<html><body><article>${PARAGRAPH.repeat(Math.ceil(bytes / PARAGRAPH.length))}</article></body></html>`;
// One enormous list can't be split into batches, so it stays slow to convert.
const hostilePage = `<html><body><ul>${"<li>item <b>x</b></li>".repeat(120_000)}</ul></body></html>`;

const job = (html: string): Parameters<typeof extractInWorker>[0] => ({
  body: Buffer.from(html),
  contentType: "text/html",
  mode: "full"
});

describe("extractInWorker", () => {
  it("returns the same result as converting directly", async () => {
    const r = await extractInWorker(job("<html><body><h1>Hi</h1></body></html>"), 10_000);
    expect(r).toMatchObject({ extraction: "full", markdown: "# Hi" });
  });

  it("kills a job over budget, keeps the event loop free, and still works afterwards", async () => {
    let ticks = 0;
    const ticker = setInterval(() => (ticks += 1), 10);
    const started = Date.now();

    const err = await extractInWorker(job(hostilePage), 300).catch((e: unknown) => e);

    clearInterval(ticker);
    expect(err).toBeInstanceOf(GuardError);
    expect((err as GuardError).code).toBe("PROCESSING_LIMIT");
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(ticks).toBeGreaterThan(5);

    const after = await extractInWorker(
      job("<html><body><p>ok</p></body></html>"),
      10_000
    );
    expect(after.markdown).toBe("ok");
  });

  it("handles concurrent jobs beyond the pool size", async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        extractInWorker(job(`<html><body><p>page ${i}</p></body></html>`), 15_000)
      )
    );
    expect(results.map((r) => r.markdown)).toEqual(
      Array.from({ length: 8 }, (_, i) => `page ${i}`)
    );
  });
});

describe("htmlToMarkdown on large pages", () => {
  it("converts a large flat page in linear-ish time", () => {
    const started = Date.now();
    const md = htmlToMarkdown(flatPage(5_000_000));
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(md.match(/quick brown fox/g)?.length).toBeGreaterThan(50_000);
  });

  it("handles valid HTML5 that omits <head> and <body>", () => {
    // Real minified docs pages do this, and linkedom leaves document.body empty.
    const body = PARAGRAPH.trim().repeat(2_000);
    const md = htmlToMarkdown(
      `<!doctype html><html lang=en><meta charset=utf-8><title>Docs</title>${body}`
    );

    expect(md.match(/quick brown fox/g)?.length).toBe(2_000);
  });

  it("batches to the same text as converting all at once", () => {
    const blocks = Array.from(
      { length: 2_000 },
      (_, i) =>
        `<h2>Section ${i}</h2><p>Text with <a href="https://x.test/${i}">a link</a>.</p><pre><code>code_${i}()</code></pre><ul><li>one</li><li>two</li></ul>`
    ).join("");
    const md = htmlToMarkdown(`<html><body><main>${blocks}</main></body></html>`);

    expect(md).toContain("## Section 1999");
    expect(md).toContain("[a link](https://x.test/0)");
    expect(md).toContain("```\ncode_250()\n```");
    expect(md).not.toMatch(/\n{3,}/);
  });
});

describe("through fetch_url", () => {
  let server: http.Server | undefined;

  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  const cfg: SafeFetchConfig = {
    allowLocal: true,
    allowlist: [],
    maxBytes: 10_000_000,
    timeoutMs: 500,
    maxRedirects: 5
  };

  it("refuses with PROCESSING_LIMIT near the deadline instead of hanging", async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(hostilePage);
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const started = Date.now();

    const result = await runFetchUrl({ url, extract: "full" }, cfg);

    expect(result.isError).toBe(true);
    expect(result.structuredContent?.error?.code).toBe("PROCESSING_LIMIT");
    expect(result.structuredContent?.error?.retryable).toBe(false);
    expect(Date.now() - started).toBeLessThan(5_000);
  });
});
