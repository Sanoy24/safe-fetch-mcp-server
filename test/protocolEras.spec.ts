import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as http from "node:http";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { Client as ModernClient } from "@modelcontextprotocol/client";
import { StreamableHTTPClientTransport as ModernHttp } from "@modelcontextprotocol/client";
import { StdioClientTransport as ModernStdio } from "@modelcontextprotocol/client/stdio";
import { Client as OldClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport as OldHttp } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioClientTransport as OldStdio } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createHttpApp } from "../src/httpApp.js";

// The same tool must work for clients of both protocol eras, on both transports. The old
// client is the published v1 SDK, so these are real 2025-era clients. Stdio specs launch
// the compiled server (npm test builds first).

const MODERN = "2026-07-28";
const SERVER = join(import.meta.dirname, "..", "dist", "index.js");
const TOKEN = "correct-horse-battery-staple";
const modernOptions = { versionNegotiation: { mode: { pin: MODERN } } };

interface AnyClient {
  listTools(): Promise<{ tools: Array<{ name: string; outputSchema?: unknown }> }>;
  callTool(params: {
    name: string;
    arguments: Record<string, unknown>;
  }): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

let app: http.Server;
let mcpUrl: URL;
let tokenApp: http.Server;
let tokenUrl: URL;
let page: http.Server;
let pageUrl: string;

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

const httpConfig = {
  host: "127.0.0.1",
  port: 0,
  allowedOrigins: [],
  allowedHosts: [],
  trustProxyHops: 0,
  rateLimitMax: 1000,
  rateLimitWindowMs: 60_000
};

beforeAll(async () => {
  app = createHttpApp(httpConfig).listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => app.once("listening", resolve));
  mcpUrl = new URL(`http://127.0.0.1:${(app.address() as AddressInfo).port}/mcp`);

  tokenApp = createHttpApp({ ...httpConfig, httpToken: TOKEN }).listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => tokenApp.once("listening", resolve));
  tokenUrl = new URL(`http://127.0.0.1:${(tokenApp.address() as AddressInfo).port}/mcp`);

  page = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("hello from the page");
  });
  pageUrl = `http://127.0.0.1:${await listen(page)}/`;
});

afterAll(async () => {
  for (const server of [app, tokenApp, page]) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

const stdioParams = {
  command: process.execPath,
  args: [SERVER],
  env: { ...process.env, SAFE_FETCH_ALLOW_LOCAL: "true" } as Record<string, string>,
  stderr: "ignore" as const
};

const clients: Array<[string, () => Promise<AnyClient>]> = [
  [
    "2025-era client over stdio",
    async () => {
      const client = new OldClient({ name: "old", version: "0" });
      await client.connect(new OldStdio(stdioParams));
      return client as unknown as AnyClient;
    }
  ],
  [
    "2026-07-28 client over stdio",
    async () => {
      const client = new ModernClient({ name: "modern", version: "0" }, modernOptions);
      await client.connect(new ModernStdio(stdioParams));
      expect(client.getNegotiatedProtocolVersion()).toBe(MODERN);
      return client as unknown as AnyClient;
    }
  ],
  [
    "2025-era client over HTTP",
    async () => {
      const client = new OldClient({ name: "old", version: "0" });
      await client.connect(new OldHttp(mcpUrl));
      return client as unknown as AnyClient;
    }
  ],
  [
    "2026-07-28 client over HTTP",
    async () => {
      const client = new ModernClient({ name: "modern", version: "0" }, modernOptions);
      await client.connect(new ModernHttp(mcpUrl));
      expect(client.getNegotiatedProtocolVersion()).toBe(MODERN);
      return client as unknown as AnyClient;
    }
  ]
];

describe.each(clients)("%s", (_label, connect) => {
  let client: AnyClient;

  beforeAll(async () => {
    client = await connect();
  }, 20_000);

  afterAll(async () => {
    await client.close();
  });

  it("lists fetch_url with an output schema", async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "fetch_url");
    expect(tool?.outputSchema).toBeDefined();
  });

  it("refuses cloud metadata with the stable error shape", async () => {
    const result = await client.callTool({
      name: "fetch_url",
      arguments: { url: "http://169.254.169.254/latest/meta-data/" }
    });
    expect(result["isError"]).toBe(true);
    expect(result["structuredContent"]).toMatchObject({
      error: { code: "POLICY_REJECTED", retryable: false }
    });
  });

  it("rejects invalid arguments", async () => {
    const outcome = await client
      .callTool({ name: "fetch_url", arguments: { url: 42 } })
      .then(
        (result) => result["isError"] === true,
        () => true
      );
    expect(outcome).toBe(true);
  });
});

describe.each(clients.slice(0, 2))("%s, fetching a page", (_label, connect) => {
  it("returns framed text and structured content", async () => {
    const client = await connect();
    const result = await client.callTool({
      name: "fetch_url",
      arguments: { url: pageUrl }
    });
    expect(result["isError"]).toBeFalsy();
    expect(JSON.stringify(result["structuredContent"])).toContain("hello from the page");
    expect(JSON.stringify(result["structuredContent"])).toContain("<<<external-content");
    await client.close();
  }, 20_000);
});

describe("bearer token, for both eras", () => {
  const authorized = { headers: { Authorization: `Bearer ${TOKEN}` } };

  it("lets each era in with the token", async () => {
    const old = new OldClient({ name: "old", version: "0" });
    await old.connect(new OldHttp(tokenUrl, { requestInit: authorized }));
    expect((await old.listTools()).tools.length).toBeGreaterThan(0);
    await old.close();

    const modern = new ModernClient({ name: "modern", version: "0" }, modernOptions);
    await modern.connect(new ModernHttp(tokenUrl, { requestInit: authorized }));
    expect((await modern.listTools()).tools.length).toBeGreaterThan(0);
    await modern.close();
  });

  it("keeps each era out without it", async () => {
    const old = new OldClient({ name: "old", version: "0" });
    await expect(old.connect(new OldHttp(tokenUrl))).rejects.toThrow();

    const modern = new ModernClient({ name: "modern", version: "0" }, modernOptions);
    await expect(modern.connect(new ModernHttp(tokenUrl))).rejects.toThrow();
  });
});
