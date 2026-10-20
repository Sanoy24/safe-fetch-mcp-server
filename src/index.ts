#!/usr/bin/env node
import type { Server } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";
import { ConfigError, getConfig, isLoopbackHost, loadHttpConfig } from "./config.js";
import { createHttpApp } from "./httpApp.js";

// stdout is reserved for MCP protocol traffic in stdio mode; log only to stderr.

async function startStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("safe-fetch-mcp-server running on stdio");
}

async function startHttp(): Promise<Server> {
  // The rate limiter for the /mcp endpoint lives inside createHttpApp
  // (httpApp.ts), not here — see SAFE_FETCH_RATE_LIMIT_MAX/_WINDOW_MS.
  const httpConfig = loadHttpConfig();
  if (!isLoopbackHost(httpConfig.host)) {
    console.error(
      `WARNING: HTTP mode is bound to ${httpConfig.host}, not loopback. This server has no ` +
        "authentication: anyone who can reach this address can make it fetch URLs. " +
        "Only do this behind your own authenticating proxy."
    );
  }
  const app = createHttpApp(httpConfig);

  return new Promise<Server>((resolve, reject) => {
    const httpServer = app.listen(httpConfig.port, httpConfig.host, () => {
      console.error(
        `safe-fetch-mcp-server listening on http://${httpConfig.host}:${httpConfig.port}/mcp`
      );
      resolve(httpServer);
    });
    // Logs unconditionally: reject() only affects this startup promise and becomes
    // a safe no-op once it has settled, so without a log a post-startup error
    // (e.g. EMFILE during accept()) would otherwise vanish silently.
    httpServer.on("error", (err) => {
      console.error("HTTP server error:", err);
      reject(err);
    });
  });
}

function shutDownOnSignal(httpServer: Server): void {
  const shutDown = (signal: NodeJS.Signals): void => {
    console.error(`Received ${signal}, shutting down.`);
    httpServer.close(() => process.exit(0));
    // Don't let a stuck keep-alive connection block exit forever.
    httpServer.closeIdleConnections();
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.once("SIGINT", shutDown);
  process.once("SIGTERM", shutDown);
}

// In stdio mode the client owns our stdout. If it disconnects while a response is being
// written, the write fails with EPIPE. That just means the client is gone, so exit
// quietly instead of crashing with a stack trace.
process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE" || err.code === "ERR_STREAM_DESTROYED") process.exit(0);
  throw err;
});

async function main(): Promise<void> {
  // --compat mirrors SAFE_FETCH_COMPAT_TOOL=true, so switching from the reference fetch
  // server is a one-line change to the args. Set before the config is first read.
  if (process.argv.includes("--compat")) process.env["SAFE_FETCH_COMPAT_TOOL"] = "true";

  // Validate every setting before accepting any request.
  getConfig();

  // --http is a shell-agnostic alternative to TRANSPORT=http (which only works as an
  // inline env-var prefix in POSIX shells, not PowerShell/cmd.exe).
  const wantsHttp =
    process.env["TRANSPORT"] === "http" || process.argv.includes("--http");
  if (wantsHttp) {
    shutDownOnSignal(await startHttp());
  } else {
    await startStdio();
  }
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) {
    console.error(`safe-fetch-mcp-server: invalid configuration. ${err.message}`);
  } else {
    console.error("Fatal error starting safe-fetch-mcp-server:", err);
  }
  process.exit(1);
});
