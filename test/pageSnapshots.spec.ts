import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { runFetchUrl } from "../src/tools/fetchUrl.js";
import {
  clearPageSnapshots,
  getSnapshot,
  saveSnapshot,
  type PageSnapshot
} from "../src/content/pageSnapshots.js";
import { clearRobotsCache } from "../src/security/robots.js";
import { loadConfig, type SafeFetchConfig } from "../src/config.js";

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    snapshotTtlMs: 60_000,
    ...overrides
  };
}

let server: http.Server | undefined;
let requests = 0;

beforeEach(() => {
  clearPageSnapshots();
  clearRobotsCache();
  requests = 0;
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(async () => {
  vi.restoreAllMocks();
  if (!server) return;
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

/** Every request returns a different version of a long page, like a live site. */
async function serveChangingPage(): Promise<string> {
  server = http.createServer((req, res) => {
    if (req.url === "/robots.txt") {
      res.writeHead(404);
      res.end();
      return;
    }
    requests += 1;
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`v${requests} `.repeat(1_000));
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/page`;
}

const textOf = (result: Awaited<ReturnType<typeof runFetchUrl>>): string =>
  result.content[0]?.text ?? "";

describe("stable pagination", () => {
  it("reads later chunks from the same version, without downloading again", async () => {
    const url = await serveChangingPage();
    const first = await runFetchUrl({ url, max_chars: 100 }, testConfig());
    const second = await runFetchUrl(
      { url, max_chars: 100, start_index: first.structuredContent?.nextStartIndex },
      testConfig()
    );

    expect(requests).toBe(1);
    expect(textOf(second)).toContain("v1 ");
    expect(textOf(second)).not.toContain("v2 ");
    expect(first.structuredContent?.fromSnapshot).toBeUndefined();
    expect(second.structuredContent?.fromSnapshot).toBe(true);
    expect(second.structuredContent?.totalChars).toBe(
      first.structuredContent?.totalChars
    );
    expect(second.structuredContent?.finalUrl).toBe(first.structuredContent?.finalUrl);
  });

  it("returns the same text as one large read", async () => {
    const url = await serveChangingPage();
    const whole = (await runFetchUrl({ url }, testConfig())).structuredContent
      ?.totalChars;
    clearPageSnapshots();
    let start: number | null | undefined = 0;
    let chars = 0;
    while (start !== null && start !== undefined) {
      const part: Awaited<ReturnType<typeof runFetchUrl>> = await runFetchUrl(
        { url, max_chars: 700, start_index: start },
        testConfig()
      );
      const { startIndex, nextStartIndex, totalChars } = part.structuredContent ?? {};
      chars += (nextStartIndex ?? totalChars ?? 0) - (startIndex ?? 0);
      start = nextStartIndex;
    }
    expect(chars).toBe(whole);
    expect(requests).toBe(2); // one for the whole read, one for all the chunks
  });

  it("gets a fresh copy when starting again from the beginning", async () => {
    const url = await serveChangingPage();
    await runFetchUrl({ url, max_chars: 100 }, testConfig());
    const again = await runFetchUrl({ url, max_chars: 100 }, testConfig());
    expect(requests).toBe(2);
    expect(textOf(again)).toContain("v2 ");

    const next = await runFetchUrl(
      { url, max_chars: 100, start_index: 100 },
      testConfig()
    );
    expect(textOf(next)).toContain("v2 ");
    expect(requests).toBe(2);
  });

  it("downloads again once the copy has expired", async () => {
    const url = await serveChangingPage();
    const now = vi.spyOn(Date, "now");
    const base = Date.now();
    now.mockReturnValue(base);
    await runFetchUrl({ url, max_chars: 100 }, testConfig());
    now.mockReturnValue(base + 60_001);
    const late = await runFetchUrl(
      { url, max_chars: 100, start_index: 100 },
      testConfig()
    );
    expect(requests).toBe(2);
    expect(late.structuredContent?.fromSnapshot).toBeUndefined();
  });

  it("can be turned off", async () => {
    const url = await serveChangingPage();
    const cfg = testConfig({ snapshotTtlMs: 0 });
    await runFetchUrl({ url, max_chars: 100 }, cfg);
    await runFetchUrl({ url, max_chars: 100, start_index: 100 }, cfg);
    expect(requests).toBe(2);
  });

  it("doesn't share a copy across different arguments", async () => {
    const url = await serveChangingPage();
    await runFetchUrl({ url, max_chars: 100 }, testConfig());
    await runFetchUrl(
      { url, max_chars: 100, start_index: 100, format: "raw" },
      testConfig()
    );
    expect(requests).toBe(2);
    await runFetchUrl(
      { url, max_chars: 100, start_index: 100, max_bytes: 3_000 },
      testConfig()
    );
    expect(requests).toBe(3);
  });

  it("doesn't keep a copy of a page that fit in one read", async () => {
    const url = await serveChangingPage();
    await runFetchUrl({ url, max_chars: 1_000_000 }, testConfig());
    await runFetchUrl({ url, start_index: 100 }, testConfig());
    expect(requests).toBe(2);
  });

  it("doesn't keep a copy of an error page", async () => {
    server = http.createServer((_req, res) => {
      requests += 1;
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("x".repeat(5_000));
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    await runFetchUrl({ url, max_chars: 100 }, testConfig());
    await runFetchUrl({ url, max_chars: 100, start_index: 100 }, testConfig());
    expect(requests).toBe(2);
  });
});

describe("a snapshot is never a way around the guard", () => {
  it("refuses a later chunk once the host is no longer allowed", async () => {
    const url = await serveChangingPage();
    await runFetchUrl({ url, max_chars: 100 }, testConfig());

    const refused = await runFetchUrl(
      { url, max_chars: 100, start_index: 100 },
      testConfig({ denylist: ["127.0.0.1"] })
    );
    expect(refused.isError).toBe(true);
    expect(refused.structuredContent?.error?.code).toBe("POLICY_REJECTED");
    expect(textOf(refused)).not.toContain("v1 ");
  });

  it("re-checks the whole redirect chain, not just the first URL", async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/end" });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("x".repeat(5_000));
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await runFetchUrl({ url: `${origin}/start`, max_chars: 100 }, testConfig());

    // Local access removed: the stored chain is refused on its first hop.
    const refused = await runFetchUrl(
      { url: `${origin}/start`, max_chars: 100, start_index: 100 },
      testConfig({ allowLocal: false })
    );
    expect(refused.structuredContent?.error?.code).toBe("POLICY_REJECTED");
  });

  it("re-checks robots.txt", async () => {
    let disallow = false;
    server = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(
        req.url === "/robots.txt"
          ? `User-agent: *\nDisallow: ${disallow ? "/" : "/nothing"}`
          : "x".repeat(5_000)
      );
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/page`;
    const cfg = testConfig({ robots: "respect" });
    await runFetchUrl({ url, max_chars: 100 }, cfg);

    disallow = true;
    clearRobotsCache();
    const refused = await runFetchUrl({ url, max_chars: 100, start_index: 100 }, cfg);
    expect(refused.structuredContent?.error?.code).toBe("ROBOTS_DISALLOWED");
  });

  it("is framed with a fresh marker, and logged", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const url = await serveChangingPage();
    const first = await runFetchUrl({ url, max_chars: 100 }, testConfig());
    const second = await runFetchUrl(
      { url, max_chars: 100, start_index: 100 },
      testConfig()
    );
    const marker = (text: string): string | undefined =>
      /<<<external-content ([0-9a-f]+)>>>/.exec(text)?.[1];
    expect(marker(textOf(second))).toBeDefined();
    expect(marker(textOf(second))).not.toBe(marker(textOf(first)));

    const lastLine = String(spy.mock.calls.at(-1)?.[0]);
    expect(lastLine).toContain("outcome=allowed");
    expect(lastLine).toContain("fromSnapshot=true");
    expect(lastLine).not.toContain("peerIps");
  });
});

describe("snapshot store limits", () => {
  const page = (chars: number): PageSnapshot => ({
    text: "x".repeat(chars),
    status: 200,
    finalUrl: "https://example.com/",
    contentType: "text/plain",
    bytes: chars,
    truncated: false,
    extraction: "none",
    hints: [],
    metadata: {},
    urlChain: ["https://example.com/"]
  });
  const cfg = { snapshotTtlMs: 60_000 };

  it("evicts the least recently used beyond the entry limit", () => {
    for (let i = 0; i < 50; i += 1) saveSnapshot(`k${i}`, page(1), cfg);
    getSnapshot("k0");
    saveSnapshot("new", page(1), cfg);
    expect(getSnapshot("k0")).toBeDefined();
    expect(getSnapshot("k1")).toBeUndefined();
    expect(getSnapshot("new")).toBeDefined();
  });

  it("evicts to stay under the total size limit", () => {
    saveSnapshot("a", page(30_000_000), cfg);
    saveSnapshot("b", page(30_000_000), cfg);
    expect(getSnapshot("a")).toBeUndefined();
    expect(getSnapshot("b")).toBeDefined();
  });

  it("refuses one page larger than the whole limit", () => {
    saveSnapshot("huge", page(50_000_001), cfg);
    expect(getSnapshot("huge")).toBeUndefined();
  });
});

describe("configuration", () => {
  it("defaults to five minutes and validates the setting", () => {
    expect(loadConfig({}).snapshotTtlMs).toBe(300_000);
    expect(loadConfig({ SAFE_FETCH_SNAPSHOT_TTL_MS: "0" }).snapshotTtlMs).toBe(0);
    expect(() => loadConfig({ SAFE_FETCH_SNAPSHOT_TTL_MS: "soon" })).toThrow(
      /SAFE_FETCH_SNAPSHOT_TTL_MS/
    );
  });
});
