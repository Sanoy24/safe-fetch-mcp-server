import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

// stdout is reserved for MCP protocol traffic; log only to stderr.
async function main(): Promise<void> {
  const transport = process.env["TRANSPORT"];

  if (transport === "http") {
    // Streamable HTTP transport lands in a later increment (Milestone 4).
    console.error("TRANSPORT=http is not implemented yet; falling back to stdio.");
  }

  const server = createServer();
  const stdioTransport = new StdioServerTransport();
  await server.connect(stdioTransport);
  console.error("safe-fetch-mcp-server running on stdio");
}

main().catch((err: unknown) => {
  console.error("Fatal error starting safe-fetch-mcp-server:", err);
  process.exit(1);
});
