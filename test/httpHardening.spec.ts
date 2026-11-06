import { describe, it, expect, afterEach, vi } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/client";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { createHttpApp } from "../src/httpApp.js";
import { ConfigError, loadHttpConfig, type HttpTransportConfig } from "../src/config.js";

const TOKEN = "correct-horse-battery-staple";

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "http-hardening-test", version: "0.0.1" }
  }
};

let server: http.Server | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  if (!server) return;
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

async function start(overrides: Partial<HttpTransportConfig> = {}): Promise<number> {
  const app = createHttpApp({
    host: "127.0.0.1",
    port: 0,
    allowedOrigins: [],
    allowedHosts: [],
    trustProxyHops: 0,
    rateLimitMax: 1000,
    rateLimitWindowMs: 60_000,
    ...overrides
  });
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server?.once("listening", resolve));
  return (server.address() as AddressInfo).port;
}

// A raw request, because fetch() won't let a test set the Host header.
function post(
  port: number,
  headers: Record<string, string>,
  body: unknown = INITIALIZE
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/mcp",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          ...headers
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8")
          })
        );
      }
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

describe("HTTP mode bearer token", () => {
  it("refuses a request with no token and says how to authenticate", async () => {
    const port = await start({ httpToken: TOKEN });
    const res = await post(port, {});
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe("Bearer");
    expect(res.body).not.toContain(TOKEN);
  });

  it.each([
    ["a wrong token", `Bearer ${TOKEN}x`],
    ["a prefix of the token", `Bearer ${TOKEN.slice(0, -1)}`],
    ["the wrong scheme", `Basic ${TOKEN}`],
    ["a bare token", TOKEN],
    ["an empty token", "Bearer "]
  ])("refuses %s", async (_label, authorization) => {
    const port = await start({ httpToken: TOKEN });
    const res = await post(port, { Authorization: authorization });
    expect(res.status).toBe(401);
  });

  it("accepts the right token, with the scheme in any case", async () => {
    const port = await start({ httpToken: TOKEN });
    expect((await post(port, { Authorization: `Bearer ${TOKEN}` })).status).toBe(200);
    expect((await post(port, { Authorization: `bearer ${TOKEN}` })).status).toBe(200);
  });

  it("works through a real MCP client", async () => {
    const port = await start({ httpToken: TOKEN });
    const client = new Client({ name: "http-hardening-test", version: "0.0.1" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${port}/mcp`),
      { requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } } }
    );
    await client.connect(transport);
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain("fetch_url");
    await client.close();
  });

  it("rate-limits failed attempts", async () => {
    const port = await start({ httpToken: TOKEN, rateLimitMax: 2 });
    expect((await post(port, {})).status).toBe(401);
    expect((await post(port, {})).status).toBe(401);
    expect((await post(port, {})).status).toBe(429);
  });

  it("lets a browser preflight through and allows the Authorization header", async () => {
    const origin = "https://app.example";
    const port = await start({ httpToken: TOKEN, allowedOrigins: [origin] });
    const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "OPTIONS",
      headers: { Origin: origin, "Access-Control-Request-Method": "POST" }
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
  });

  it("needs no token when none is configured", async () => {
    const port = await start();
    expect((await post(port, {})).status).toBe(200);
  });
});

describe("SAFE_FETCH_ALLOWED_HOSTS", () => {
  it("accepts a configured hostname, on any port", async () => {
    const port = await start({ host: "0.0.0.0", allowedHosts: ["mcp.example.com"] });
    expect((await post(port, { Host: "mcp.example.com" })).status).toBe(200);
    expect((await post(port, { Host: "mcp.example.com:8443" })).status).toBe(200);
  });

  it("still refuses any other hostname", async () => {
    const port = await start({ host: "0.0.0.0", allowedHosts: ["mcp.example.com"] });
    expect((await post(port, { Host: "evil.example" })).status).toBe(403);
    expect((await post(port, { Host: "mcp.example.com.evil.example" })).status).toBe(403);
  });
});

describe("SAFE_FETCH_TRUST_PROXY", () => {
  it("ignores X-Forwarded-For by default, so it can't be used to dodge the limit", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined); // limiter's warning
    const port = await start({ rateLimitMax: 1 });
    expect((await post(port, { "X-Forwarded-For": "203.0.113.1" })).status).toBe(200);
    expect((await post(port, { "X-Forwarded-For": "203.0.113.2" })).status).toBe(429);
  });

  it("limits each client separately behind a trusted proxy", async () => {
    const port = await start({ rateLimitMax: 1, trustProxyHops: 1 });
    expect((await post(port, { "X-Forwarded-For": "203.0.113.1" })).status).toBe(200);
    expect((await post(port, { "X-Forwarded-For": "203.0.113.2" })).status).toBe(200);
    expect((await post(port, { "X-Forwarded-For": "203.0.113.1" })).status).toBe(429);
  });

  it("uses only the hop the proxy added, not one the client supplied", async () => {
    const port = await start({ rateLimitMax: 1, trustProxyHops: 1 });
    const spoofed = (claimed: string): Promise<{ status: number }> =>
      post(port, { "X-Forwarded-For": `${claimed}, 203.0.113.9` });
    expect((await spoofed("198.51.100.1")).status).toBe(200);
    expect((await spoofed("198.51.100.2")).status).toBe(429);
  });
});

describe("per-request cleanup", () => {
  it("closes the per-request server once the response has finished", async () => {
    const close = vi.spyOn(McpServer.prototype, "close");
    const port = await start();
    expect((await post(port, {})).status).toBe(200);
    await vi.waitFor(() => expect(close).toHaveBeenCalledTimes(1));
  });

  it("answers without internal detail when serving fails", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(McpServer.prototype, "connect").mockRejectedValue(new Error("boom"));
    const port = await start();
    const res = await post(port, {});
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(res.body).not.toContain("boom");
  });
});

describe("loadHttpConfig: non-loopback binding", () => {
  it("refuses to bind beyond loopback without a token", () => {
    expect(() => loadHttpConfig({ HOST: "0.0.0.0" })).toThrow(ConfigError);
    expect(() => loadHttpConfig({ HOST: "0.0.0.0" })).toThrow(/SAFE_FETCH_HTTP_TOKEN/);
    expect(() => loadHttpConfig({ HOST: "192.168.1.10" })).toThrow(ConfigError);
  });

  it("allows it with a token, or an explicit opt-out", () => {
    expect(
      loadHttpConfig({ HOST: "0.0.0.0", SAFE_FETCH_HTTP_TOKEN: TOKEN }).httpToken
    ).toBe(TOKEN);
    expect(
      loadHttpConfig({ HOST: "0.0.0.0", SAFE_FETCH_HTTP_INSECURE: "true" }).host
    ).toBe("0.0.0.0");
  });

  it("stays open on loopback, the default", () => {
    expect(loadHttpConfig({}).httpToken).toBeUndefined();
    expect(loadHttpConfig({ HOST: "localhost" }).host).toBe("localhost");
  });

  it("rejects a short token without echoing it", () => {
    const short = "hunter2";
    expect(() => loadHttpConfig({ SAFE_FETCH_HTTP_TOKEN: short })).toThrow(ConfigError);
    try {
      loadHttpConfig({ SAFE_FETCH_HTTP_TOKEN: short });
    } catch (err) {
      expect((err as Error).message).not.toContain(short);
    }
  });

  it("rejects a token containing whitespace", () => {
    expect(() =>
      loadHttpConfig({ SAFE_FETCH_HTTP_TOKEN: "two words that are long enough" })
    ).toThrow(ConfigError);
  });
});

describe("loadHttpConfig: other HTTP settings", () => {
  it("parses allowed hosts", () => {
    expect(
      loadHttpConfig({ SAFE_FETCH_ALLOWED_HOSTS: "MCP.example.com, [::2], 10.0.0.5" })
        .allowedHosts
    ).toEqual(["mcp.example.com", "[::2]", "10.0.0.5"]);
  });

  it.each(["https://mcp.example.com", "mcp.example.com:8443", "*.example.com"])(
    "rejects the allowed host %s",
    (entry) => {
      expect(() => loadHttpConfig({ SAFE_FETCH_ALLOWED_HOSTS: entry })).toThrow(
        /SAFE_FETCH_ALLOWED_HOSTS/
      );
    }
  );

  it("parses proxy hops, defaulting to none", () => {
    expect(loadHttpConfig({}).trustProxyHops).toBe(0);
    expect(loadHttpConfig({ SAFE_FETCH_TRUST_PROXY: "2" }).trustProxyHops).toBe(2);
    expect(() => loadHttpConfig({ SAFE_FETCH_TRUST_PROXY: "true" })).toThrow(ConfigError);
  });
});
