import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHttpApp } from "../src/httpApp.js";
import type { HttpTransportConfig } from "../src/config.js";

function testHttpConfig(overrides: Partial<HttpTransportConfig> = {}): HttpTransportConfig {
  return { host: "127.0.0.1", port: 0, allowedOrigins: [], ...overrides };
}

describe("Streamable HTTP transport", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = createHttpApp(testHttpConfig());
    server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const port = (server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function connectClient(): Promise<Client> {
    const client = new Client({ name: "http-transport-test", version: "0.0.1" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    await client.connect(transport);
    return client;
  }

  it("lists the fetch_url tool over HTTP", async () => {
    const client = await connectClient();
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain("fetch_url");
    await client.close();
  });

  it("refuses an SSRF target over HTTP, same as stdio", async () => {
    const client = await connectClient();
    const result = await client.callTool({
      name: "fetch_url",
      arguments: { url: "http://169.254.169.254/latest/meta-data/" }
    });
    expect(result["isError"]).toBe(true);
    await client.close();
  });

  it("rejects a request bearing a disallowed Origin header", async () => {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        origin: "https://evil.example"
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 })
    });
    expect(response.status).toBe(403);
  });

  it("rejects a request with a spoofed Host header (DNS-rebinding protection)", async () => {
    const port = Number(new URL(baseUrl).port);
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/mcp",
          method: "POST",
          headers: { Host: "evil.example", "content-type": "application/json" }
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        }
      );
      req.on("error", reject);
      req.end(JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }));
    });
    expect(status).toBe(403);
  });

  it("returns 405 for GET and DELETE on /mcp (stateless mode has no session to resume/close)", async () => {
    const getRes = await fetch(`${baseUrl}/mcp`, { method: "GET" });
    expect(getRes.status).toBe(405);

    const deleteRes = await fetch(`${baseUrl}/mcp`, { method: "DELETE" });
    expect(deleteRes.status).toBe(405);
  });
});
