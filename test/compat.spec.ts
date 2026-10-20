import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";
import { loadConfig, type SafeFetchConfig } from "../src/config.js";

// Opt-in drop-in compatibility with the reference mcp-server-fetch: a `fetch` tool with
// its exact arguments (url, max_length=5000, start_index, raw) and a `fetch` prompt. Both
// run through the same guard as fetch_url; compatibility never means weaker security.

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

async function connect(config: SafeFetchConfig): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer({ config }).connect(serverSide);
  const client = new Client({ name: "compat-test", version: "0" });
  await client.connect(clientSide);
  return client;
}

let server: http.Server | undefined;
let base = "";

beforeEach(async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html><body><h1>Title</h1><p>" + "x".repeat(6_000) + "</p></body></html>");
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = undefined;
});

function textOf(result: unknown): string {
  const content = (result as { content?: Array<{ text?: string }> }).content;
  return content?.map((c) => c.text ?? "").join("") ?? "";
}

describe("compat mode off (default)", () => {
  it("exposes only fetch_url and no prompts", async () => {
    const client = await connect(testConfig());

    const tools = (await client.listTools()).tools.map((t) => t.name);
    expect(tools).toEqual(["fetch_url"]);
    await expect(client.listPrompts()).rejects.toThrow();
    await client.close();
  });
});

describe("compat mode on (SAFE_FETCH_COMPAT_TOOL / --compat)", () => {
  it("adds a `fetch` tool with the upstream argument names and defaults", async () => {
    const client = await connect(testConfig({ compatFetchTool: true }));

    const tools = (await client.listTools()).tools;
    expect(tools.map((t) => t.name).sort()).toEqual(["fetch", "fetch_url"]);
    const fetchTool = tools.find((t) => t.name === "fetch");
    expect(Object.keys(fetchTool?.inputSchema.properties ?? {}).sort()).toEqual([
      "max_length",
      "raw",
      "start_index",
      "url"
    ]);
    expect(fetchTool?.annotations?.readOnlyHint).toBe(true);
    await client.close();
  });

  it("returns at most max_length characters, 5000 by default, and pages with start_index", async () => {
    const client = await connect(testConfig({ compatFetchTool: true }));

    const first = await client.callTool({
      name: "fetch",
      arguments: { url: `${base}/` }
    });
    const firstMeta = first.structuredContent as { nextStartIndex: number | null };
    expect(firstMeta.nextStartIndex).toBe(5000);

    const second = await client.callTool({
      name: "fetch",
      arguments: { url: `${base}/`, start_index: 5000, max_length: 100 }
    });
    expect((second.structuredContent as { startIndex: number }).startIndex).toBe(5000);
    await client.close();
  });

  it("maps raw: true to unconverted content", async () => {
    const client = await connect(testConfig({ compatFetchTool: true }));

    const raw = await client.callTool({
      name: "fetch",
      arguments: { url: `${base}/`, raw: true, max_length: 200 }
    });
    const md = await client.callTool({
      name: "fetch",
      arguments: { url: `${base}/`, max_length: 200 }
    });

    expect(textOf(raw)).toContain("<h1>Title</h1>");
    expect(textOf(md)).toContain("# Title");
    await client.close();
  });

  it("is guarded exactly like fetch_url", async () => {
    const client = await connect(
      testConfig({ compatFetchTool: true, allowLocal: false })
    );

    const refused = await client.callTool({
      name: "fetch",
      arguments: { url: "http://169.254.169.254/latest/meta-data/" }
    });

    expect(refused.isError).toBe(true);
    expect(refused.structuredContent).toEqual({
      error: { code: "POLICY_REJECTED", retryable: false }
    });
    await client.close();
  });

  it("rejects unknown arguments instead of silently ignoring them", async () => {
    const client = await connect(testConfig({ compatFetchTool: true }));

    const result = await client.callTool({
      name: "fetch",
      arguments: { url: `${base}/`, follow_robots: false }
    });

    expect(result.isError).toBe(true);
    await client.close();
  });

  it("offers a `fetch` prompt that returns the page as a user message", async () => {
    const client = await connect(testConfig({ compatFetchTool: true }));

    const prompts = (await client.listPrompts()).prompts.map((p) => p.name);
    expect(prompts).toEqual(["fetch"]);
    const prompt = await client.getPrompt({
      name: "fetch",
      arguments: { url: `${base}/` }
    });

    expect(prompt.messages[0]?.role).toBe("user");
    const content = prompt.messages[0]?.content as { type: string; text: string };
    expect(content.text).toContain("untrusted data");
    expect(content.text).toContain("# Title");
    await client.close();
  });

  it("returns the refusal text from the prompt for a blocked URL", async () => {
    const client = await connect(
      testConfig({ compatFetchTool: true, allowLocal: false })
    );

    const prompt = await client.getPrompt({
      name: "fetch",
      arguments: { url: "http://169.254.169.254/" }
    });

    const content = prompt.messages[0]?.content as { type: string; text: string };
    expect(content.text).toMatch(/^Refused:/);
    await client.close();
  });
});

describe("config", () => {
  it("SAFE_FETCH_COMPAT_TOOL defaults to off", () => {
    expect(loadConfig({}).compatFetchTool).toBe(false);
    expect(loadConfig({ SAFE_FETCH_COMPAT_TOOL: "true" }).compatFetchTool).toBe(true);
  });
});
