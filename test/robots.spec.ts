import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import * as http from "node:http";
import { isIP, type AddressInfo } from "node:net";
import { GuardError, safeFetch } from "../src/security/index.js";
import {
  clearRobotsCache,
  isPathAllowed,
  parseRobots,
  productToken
} from "../src/security/robots.js";
import { clearResponseCache } from "../src/security/responseCache.js";
import { applyCompatFlags, loadConfig, type SafeFetchConfig } from "../src/config.js";
import { runFetchUrl } from "../src/tools/fetchUrl.js";

const TOKEN = "safe-fetch-mcp-server";

function allowed(robots: string, path: string): boolean {
  return isPathAllowed(parseRobots(robots, TOKEN), path);
}

describe("parsing and matching (RFC 9309)", () => {
  it("allows everything when there are no rules", () => {
    expect(allowed("", "/x")).toBe(true);
    expect(allowed("User-agent: *\nDisallow:\n", "/x")).toBe(true);
    expect(allowed("<html>not robots</html>", "/x")).toBe(true);
  });

  it("applies the * group", () => {
    expect(allowed("User-agent: *\nDisallow: /private", "/private/a")).toBe(false);
    expect(allowed("User-agent: *\nDisallow: /private", "/public")).toBe(true);
  });

  it("prefers a group naming this client over *, case-insensitively", () => {
    const robots = `User-agent: *\nDisallow: /\n\nUser-agent: Safe-Fetch-MCP-Server\nDisallow: /own`;
    expect(allowed(robots, "/anything")).toBe(true);
    expect(allowed(robots, "/own/x")).toBe(false);
  });

  it("an empty group naming this client overrides *", () => {
    expect(allowed(`User-agent: *\nDisallow: /\n\nUser-agent: ${TOKEN}\n`, "/x")).toBe(
      true
    );
  });

  it("ignores groups for other clients", () => {
    expect(allowed("User-agent: GPTBot\nDisallow: /", "/x")).toBe(true);
    expect(allowed("User-agent: safe-fetch-other\nDisallow: /", "/x")).toBe(true);
  });

  it("shares rules between consecutive User-agent lines", () => {
    const robots = `User-agent: other\nUser-agent: ${TOKEN}\nDisallow: /a`;
    expect(allowed(robots, "/a")).toBe(false);
  });

  it("uses the longest match, and allow wins a tie", () => {
    const robots = "User-agent: *\nDisallow: /a\nAllow: /a/b\nDisallow: /a/b/c";
    expect(allowed(robots, "/a/x")).toBe(false);
    expect(allowed(robots, "/a/b/x")).toBe(true);
    expect(allowed(robots, "/a/b/c/x")).toBe(false);
    expect(allowed("User-agent: *\nDisallow: /a\nAllow: /a", "/a")).toBe(true);
  });

  it("supports * and $", () => {
    const robots = "User-agent: *\nDisallow: /*.pdf$\nDisallow: /tmp/*/secret";
    expect(allowed(robots, "/docs/a.pdf")).toBe(false);
    expect(allowed(robots, "/docs/a.pdf?x=1")).toBe(true);
    expect(allowed(robots, "/tmp/1/2/secret")).toBe(false);
    expect(allowed(robots, "/tmp/secret")).toBe(true);
  });

  it("matches the query string", () => {
    expect(allowed("User-agent: *\nDisallow: /search?q=", "/search?q=a")).toBe(false);
    expect(allowed("User-agent: *\nDisallow: /search?q=", "/search")).toBe(true);
  });

  it("treats equivalent percent-encoding as equal", () => {
    expect(allowed("User-agent: *\nDisallow: /a%7Eb", "/a~b")).toBe(false);
    expect(allowed("User-agent: *\nDisallow: /café", "/caf%C3%A9")).toBe(false);
    expect(allowed("User-agent: *\nDisallow: /a%2fb", "/a%2Fb")).toBe(false);
  });

  it("ignores comments, a byte order mark and unknown lines", () => {
    const robots = `${String.fromCharCode(0xfeff)}User-agent: * # everyone\nCrawl-delay: 5\nDisallow: /a # note\nSitemap: https://x/s.xml`;
    expect(allowed(robots, "/a")).toBe(false);
    expect(allowed(robots, "/a%20")).toBe(false);
  });

  it("handles a hostile file quickly", () => {
    const pattern = `/${"*a".repeat(400)}b`;
    const robots = `User-agent: *\n${`Disallow: ${pattern}\n`.repeat(20_000)}`;
    const started = Date.now();
    const rules = parseRobots(robots, TOKEN);
    expect(rules.length).toBeLessThanOrEqual(5_000);
    expect(isPathAllowed(rules, `/${"a".repeat(8_000)}`)).toBe(true);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("takes the product token from the User-Agent", () => {
    expect(productToken("safe-fetch-mcp-server/1.2.3 (+https://x)")).toBe(TOKEN);
    expect(productToken("MyBot/2")).toBe("MyBot");
    expect(productToken("123")).toBe(TOKEN);
  });
});

describe("fetching with SAFE_FETCH_ROBOTS=respect", () => {
  let server: http.Server | undefined;
  let requests: string[] = [];

  function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
    return {
      allowLocal: true,
      allowlist: [],
      maxBytes: 5_000_000,
      timeoutMs: 2_000,
      maxRedirects: 5,
      robots: "respect",
      ...overrides
    };
  }

  async function serve(
    robots: (res: http.ServerResponse) => void,
    page: http.RequestListener = (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("page");
    }
  ): Promise<string> {
    server = http.createServer((req, res) => {
      requests.push(req.url ?? "");
      if (req.url === "/robots.txt") robots(res);
      else page(req, res);
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  const robotsFile =
    (body: string, status = 200) =>
    (res: http.ServerResponse): void => {
      res.writeHead(status, { "content-type": "text/plain" });
      res.end(body);
    };

  const codeOf = async (promise: Promise<unknown>): Promise<string> => {
    const err = await promise.then(
      () => undefined,
      (e: unknown) => e
    );
    expect(err).toBeInstanceOf(GuardError);
    return (err as GuardError).code;
  };

  beforeEach(() => {
    clearRobotsCache();
    clearResponseCache();
    requests = [];
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  it("refuses a disallowed path without requesting it", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /secret"));
    expect(await codeOf(safeFetch(`${base}/secret`, testConfig()))).toBe(
      "ROBOTS_DISALLOWED"
    );
    expect(requests).toEqual(["/robots.txt"]);
  });

  it("fetches an allowed path", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /secret"));
    const result = await safeFetch(`${base}/open`, testConfig());
    expect(result.body.toString()).toBe("page");
  });

  it("does nothing when set to ignore, or not set", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /"));
    await safeFetch(`${base}/x`, testConfig({ robots: "ignore" }));
    const unset = testConfig();
    delete unset.robots;
    await safeFetch(`${base}/y`, unset);
    expect(requests).toEqual(["/x", "/y"]);
  });

  it("asks once per site, including for parallel fetches", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /secret"));
    await Promise.all([
      safeFetch(`${base}/1`, testConfig()),
      safeFetch(`${base}/2`, testConfig())
    ]);
    await safeFetch(`${base}/3`, testConfig());
    expect(requests.filter((r) => r === "/robots.txt")).toHaveLength(1);
  });

  it("asks again after an hour", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /secret"));
    let now = 1_000;
    await safeFetch(`${base}/1`, testConfig(), { now: () => now });
    now += 60 * 60 * 1000 + 1;
    await safeFetch(`${base}/2`, testConfig(), { now: () => now });
    expect(requests.filter((r) => r === "/robots.txt")).toHaveLength(2);
  });

  it("allows everything when robots.txt is missing or forbidden (4xx)", async () => {
    const base = await serve(robotsFile("nope", 404));
    expect((await safeFetch(`${base}/x`, testConfig())).status).toBe(200);
    server?.closeAllConnections();
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    const second = await serve(robotsFile("nope", 403));
    expect((await safeFetch(`${second}/x`, testConfig())).status).toBe(200);
  });

  it.each([500, 503, 429])(
    "refuses, retryably, when robots.txt returns %i",
    async (status) => {
      const base = await serve(robotsFile("oops", status));
      expect(await codeOf(safeFetch(`${base}/x`, testConfig()))).toBe(
        "ROBOTS_UNAVAILABLE"
      );
      expect(requests).toEqual(["/robots.txt"]);
    }
  );

  it("doesn't remember a failure", async () => {
    let status = 503;
    const base = await serve((res) => {
      res.writeHead(status);
      res.end("");
    });
    expect(await codeOf(safeFetch(`${base}/x`, testConfig()))).toBe("ROBOTS_UNAVAILABLE");
    status = 404;
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect((await safeFetch(`${base}/x`, testConfig())).status).toBe(200);
  });

  it("checks every redirect hop", async () => {
    const base = await serve(
      robotsFile("User-agent: *\nDisallow: /secret"),
      (req, res) => {
        if (req.url === "/start") {
          res.writeHead(302, { location: "/secret" });
          res.end();
          return;
        }
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("page");
      }
    );
    expect(await codeOf(safeFetch(`${base}/start`, testConfig()))).toBe(
      "ROBOTS_DISALLOWED"
    );
    expect(requests).not.toContain("/secret");
  });

  it("is not an SSRF side door: a robots.txt redirect to metadata is never followed", async () => {
    const base = await serve((res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });
    const port = new URL(base).port;
    const result = await safeFetch(`http://site.test:${port}/page`, testConfig(), {
      resolve: async (hostname) => [
        { address: isIP(hostname) ? hostname : "127.0.0.1", family: 4 }
      ]
    });
    // The bad file counts as no rules, and the page still got its own guarded fetch.
    expect(result.body.toString()).toBe("page");
    expect(requests).toEqual(["/robots.txt", "/page"]);
  });

  it("doesn't let a dead robots.txt redirect target block the page", async () => {
    const base = await serve((res) => {
      res.writeHead(302, { location: "http://127.0.0.1:1/robots.txt" });
      res.end();
    });
    expect((await safeFetch(`${base}/page`, testConfig())).status).toBe(200);
  });

  it("is not an SSRF side door: a robots.txt on a refused host is refused the same way", async () => {
    const cfg = testConfig({ allowLocal: false });
    expect(await codeOf(safeFetch("http://169.254.169.254/x", cfg))).toBe(
      "POLICY_REJECTED"
    );
  });

  it("re-checks robots.txt on a response cache hit", async () => {
    const base = await serve(robotsFile("User-agent: *\nDisallow: /secret"));
    const cfg = testConfig({
      cache: { ttlMs: 60_000, maxEntries: 10, maxBytes: 1_000_000 }
    });
    await safeFetch(`${base}/page`, cfg);
    const hit = await safeFetch(`${base}/page`, cfg);
    expect(hit.fromCache).toBe(true);

    clearRobotsCache();
    server?.removeAllListeners("request");
    server?.on("request", (_req, res: http.ServerResponse) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("User-agent: *\nDisallow: /");
    });
    expect(await codeOf(safeFetch(`${base}/page`, cfg))).toBe("ROBOTS_DISALLOWED");
  });

  it("sends the configured User-Agent on robots.txt and page requests", async () => {
    const agents: Array<string | undefined> = [];
    server = http.createServer((req, res) => {
      agents.push(req.headers["user-agent"]);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("User-agent: MyBot\nDisallow: /blocked");
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const cfg = testConfig({ userAgent: "MyBot/2.0 (+https://example.com/bot)" });

    await safeFetch(`${base}/open`, cfg);
    expect(agents).toEqual([cfg.userAgent, cfg.userAgent]);
    // The rules are matched against the configured name.
    expect(await codeOf(safeFetch(`${base}/blocked`, cfg))).toBe("ROBOTS_DISALLOWED");
  });

  it("returns a clear, non-retryable tool error", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const base = await serve(robotsFile("User-agent: *\nDisallow: /"));
    const result = await runFetchUrl({ url: `${base}/x` }, testConfig());
    expect(result.isError).toBe(true);
    expect(result.structuredContent?.error).toMatchObject({
      code: "ROBOTS_DISALLOWED",
      retryable: false
    });
  });
});

describe("configuration", () => {
  it("respects robots.txt by default and sends an identifying User-Agent", () => {
    const cfg = loadConfig({});
    expect(cfg.robots).toBe("respect");
    expect(cfg.userAgent).toMatch(
      /^safe-fetch-mcp-server\/\d+\.\d+\.\d+ \(\+https:\/\/github\.com\//
    );
  });

  it("reads SAFE_FETCH_ROBOTS and rejects anything else", () => {
    expect(loadConfig({ SAFE_FETCH_ROBOTS: "IGNORE" }).robots).toBe("ignore");
    expect(() => loadConfig({ SAFE_FETCH_ROBOTS: "off" })).toThrow(/SAFE_FETCH_ROBOTS/);
  });

  it("reads SAFE_FETCH_USER_AGENT and rejects header injection", () => {
    expect(loadConfig({ SAFE_FETCH_USER_AGENT: "MyBot/1" }).userAgent).toBe("MyBot/1");
    expect(() => loadConfig({ SAFE_FETCH_USER_AGENT: "x\r\nX-Injected: 1" })).toThrow(
      /SAFE_FETCH_USER_AGENT/
    );
    expect(() => loadConfig({ SAFE_FETCH_USER_AGENT: "a".repeat(300) })).toThrow(
      /SAFE_FETCH_USER_AGENT/
    );
    expect(() => loadConfig({ SAFE_FETCH_USER_AGENT: "café" })).toThrow(
      /SAFE_FETCH_USER_AGENT/
    );
  });

  it("maps the reference server's flags onto settings", () => {
    const env: NodeJS.ProcessEnv = {};
    applyCompatFlags(["--ignore-robots-txt", "--user-agent=MyBot/1"], env);
    expect(env["SAFE_FETCH_ROBOTS"]).toBe("ignore");
    expect(env["SAFE_FETCH_USER_AGENT"]).toBe("MyBot/1");

    const spaced: NodeJS.ProcessEnv = {};
    applyCompatFlags(["--user-agent", "Other/2", "--compat"], spaced);
    expect(spaced["SAFE_FETCH_USER_AGENT"]).toBe("Other/2");
    expect(spaced["SAFE_FETCH_COMPAT_TOOL"]).toBe("true");
  });
});
