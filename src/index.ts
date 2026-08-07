import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";
import { loadHttpConfig } from "./config.js";
import { createHttpApp } from "./httpApp.js";

// stdout is reserved for MCP protocol traffic in stdio mode; log only to stderr.

async function startStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("safe-fetch-mcp-server running on stdio");
}

async function startHttp(): Promise<void> {
  const httpConfig = loadHttpConfig();
  const app = createHttpApp(httpConfig);

  await new Promise<void>((resolve, reject) => {
    const httpServer = app.listen(httpConfig.port, httpConfig.host, () => {
      console.error(
        `safe-fetch-mcp-server listening on http://${httpConfig.host}:${httpConfig.port}/mcp`
      );
      resolve();
    });
    httpServer.on("error", reject);
  });
}

async function main(): Promise<void> {
  // --http is a shell-agnostic alternative to TRANSPORT=http (which only works as an
  // inline env-var prefix in POSIX shells, not PowerShell/cmd.exe).
  const wantsHttp = process.env["TRANSPORT"] === "http" || process.argv.includes("--http");
  if (wantsHttp) {
    await startHttp();
  } else {
    await startStdio();
  }
}

main().catch((err: unknown) => {
  console.error("Fatal error starting safe-fetch-mcp-server:", err);
  process.exit(1);
});
