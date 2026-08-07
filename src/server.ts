import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { FetchUrlInput, runFetchUrl } from "./tools/fetchUrl.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "safe-fetch-mcp-server",
    version: "0.1.0"
  });

  server.registerTool(
    "fetch_url",
    {
      title: "Fetch URL",
      description:
        "Fetch an http(s) URL and return clean markdown. Read-only; refuses private/loopback/metadata targets by default. Args: url, format ('markdown'|'raw', default 'markdown'), max_bytes?, start_index?. Returns text content plus structuredContent {status, finalUrl, contentType, bytes, truncated}. Example: fetch_url({ url: 'https://example.com' }).",
      inputSchema: FetchUrlInput,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      }
    },
    async (params) => runFetchUrl(params)
  );

  return server;
}
