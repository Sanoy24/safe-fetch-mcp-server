import { describe, it, expect, vi, afterEach, type MockInstance } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../src/server.js";
import { runFetchUrl } from "../src/tools/fetchUrl.js";
import { parseRetryAfter } from "../src/security/redirects.js";
import type { SafeFetchConfig } from "../src/config.js";

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

let server: http.Server | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  if (!server) return;
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

async function serve(handler: http.RequestListener): Promise<number> {
  server = http.createServer(handler);
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

function spyLog(): MockInstance<typeof console.error> {
  return vi.spyOn(console, "error").mockImplementation(() => undefined);
}

const logged = (spy: MockInstance<typeof console.error>): string =>
  spy.mock.calls.map((call) => String(call[0])).join("\n");

async function connectedClient(config: SafeFetchConfig): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer({ config }).connect(serverSide);
  const client = new Client({ name: "audit-test", version: "0.0.1" });
  await client.connect(clientSide);
  return client;
}

describe("audit log: successful fetches", () => {
  it("records the address actually connected to, for the operator only", async () => {
    const spy = spyLog();
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });

    // "localhost" so the address appears nowhere in the URL the model sees.
    const result = await runFetchUrl({ url: `http://localhost:${port}/` }, testConfig());

    expect(result.isError).toBeUndefined();
    expect(logged(spy)).toMatch(/peerIps=(127\.0\.0\.1|::ffff:127\.0\.0\.1)/);
    expect(JSON.stringify(result)).not.toMatch(/127\.0\.0\.1|peerIps/);
  });

  it("records every redirect hop, with query values redacted", async () => {
    const spy = spyLog();
    const port = await serve((req, res) => {
      if (req.url?.startsWith("/start")) {
        res.writeHead(302, { location: "/end?token=hop-secret" });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });

    await runFetchUrl(
      { url: `http://127.0.0.1:${port}/start?key=first-secret` },
      testConfig()
    );

    const log = logged(spy);
    expect(log).toContain("redirectChain=");
    expect(log).toContain(`/start?key=REDACTED -> http://127.0.0.1:${port}/end?token=`);
    expect(log).not.toContain("hop-secret");
    expect(log).not.toContain("first-secret");
    expect(log).toMatch(/peerIps=\S*127\.0\.0\.1,\S*127\.0\.0\.1/);
  });

  it("omits the chain when there was no redirect", async () => {
    const spy = spyLog();
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });
    await runFetchUrl({ url: `http://127.0.0.1:${port}/` }, testConfig());
    expect(logged(spy)).not.toContain("redirectChain");
  });
});

describe("audit log: refusals", () => {
  it("names the redirect target that was refused", async () => {
    const spy = spyLog();
    const port = await serve((_req, res) => {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/?a=b" });
      res.end();
    });

    const result = await runFetchUrl({ url: `http://127.0.0.1:${port}/` }, testConfig());

    expect(result.isError).toBe(true);
    const log = logged(spy);
    expect(log).toContain("redirectChain=");
    expect(log).toContain("http://169.254.169.254/latest/meta-data/?a=REDACTED");
    expect(JSON.stringify(result)).not.toContain("meta-data");
  });

  it("never logs credentials from a refused URL", async () => {
    const spy = spyLog();
    await runFetchUrl({ url: "http://alice:hunter2@example.com/" }, testConfig());
    const log = logged(spy);
    expect(log).toContain("outcome=refused");
    expect(log).not.toContain("hunter2");
    expect(log).not.toContain("alice");
  });
});

describe("audit log: invalid input", () => {
  it.each([
    ["a missing url", {}, "url:invalid_type"],
    ["a url of the wrong type", { url: 42 }, "url:invalid_type"],
    [
      "an unknown argument",
      { url: "https://example.com/", nope: 1 },
      "unrecognized_keys"
    ],
    [
      "max_chars out of range",
      { url: "https://example.com/", max_chars: -1 },
      "max_chars:"
    ]
  ])("logs %s through a real MCP client", async (_label, args, expected) => {
    const spy = spyLog();
    const client = await connectedClient(testConfig());

    const result = await client.callTool({ name: "fetch_url", arguments: args });

    expect(result.isError).toBe(true);
    const log = logged(spy);
    expect(log).toContain("outcome=refused");
    expect(log).toContain("code=INVALID_INPUT");
    expect(log).toContain(expected);
    await client.close();
  });

  it("logs issue locations only, never the values", async () => {
    const spy = spyLog();
    const client = await connectedClient(testConfig());

    await client.callTool({
      name: "fetch_url",
      arguments: { url: "not a url s3cret-value", s3cret_key: 1 }
    });

    const log = logged(spy);
    expect(log).toContain("code=INVALID_INPUT");
    expect(log).not.toContain("s3cret");
    await client.close();
  });

  it("logs nothing extra for valid input", async () => {
    const spy = spyLog();
    const client = await connectedClient(testConfig());
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });

    await client.callTool({
      name: "fetch_url",
      arguments: { url: `http://127.0.0.1:${port}/` }
    });

    expect(logged(spy)).not.toContain("INVALID_INPUT");
    await client.close();
  });

  it("logs a direct call too", async () => {
    const spy = spyLog();
    const result = await runFetchUrl({ url: 42 }, testConfig());
    expect(result.isError).toBe(true);
    expect(logged(spy)).toContain("code=INVALID_INPUT");
  });
});

describe("retryAfterSeconds", () => {
  it.each([429, 503])("is reported for a %i with Retry-After", async (status) => {
    spyLog();
    const port = await serve((_req, res) => {
      res.writeHead(status, { "content-type": "text/plain", "retry-after": "120" });
      res.end("slow down");
    });
    const result = await runFetchUrl({ url: `http://127.0.0.1:${port}/` }, testConfig());
    expect(result.structuredContent?.status).toBe(status);
    expect(result.structuredContent?.retryAfterSeconds).toBe(120);
  });

  it("is ignored on other statuses", async () => {
    spyLog();
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "retry-after": "120" });
      res.end("fine");
    });
    const result = await runFetchUrl({ url: `http://127.0.0.1:${port}/` }, testConfig());
    expect(result.structuredContent).not.toHaveProperty("retryAfterSeconds");
  });

  it("passes the declared output schema through a real client", async () => {
    spyLog();
    const client = await connectedClient(testConfig());
    const port = await serve((_req, res) => {
      res.writeHead(429, { "content-type": "text/plain", "retry-after": "5" });
      res.end("slow down");
    });
    const result = await client.callTool({
      name: "fetch_url",
      arguments: { url: `http://127.0.0.1:${port}/` }
    });
    expect(result.structuredContent).toMatchObject({ status: 429, retryAfterSeconds: 5 });
    await client.close();
  });
});

describe("parseRetryAfter", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");

  it("reads seconds and HTTP dates", () => {
    expect(parseRetryAfter("0", now)).toBe(0);
    expect(parseRetryAfter(" 90 ", now)).toBe(90);
    expect(parseRetryAfter("Thu, 01 Jan 2026 00:01:00 GMT", now)).toBe(60);
  });

  it("treats a date in the past as no wait", () => {
    expect(parseRetryAfter("Wed, 31 Dec 2025 00:00:00 GMT", now)).toBe(0);
  });

  it("ignores missing, malformed and unreasonably long values", () => {
    expect(parseRetryAfter(undefined, now)).toBeUndefined();
    expect(parseRetryAfter("soon", now)).toBeUndefined();
    expect(parseRetryAfter("-5", now)).toBeUndefined();
    expect(parseRetryAfter("1.5", now)).toBeUndefined();
    expect(parseRetryAfter("86401", now)).toBeUndefined(); // a page can't park an agent
    expect(parseRetryAfter("Fri, 01 Jan 2027 00:00:00 GMT", now)).toBeUndefined();
  });
});
