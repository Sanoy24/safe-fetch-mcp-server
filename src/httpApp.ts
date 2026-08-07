import type { Express } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { createServer } from "./server.js";
import type { HttpTransportConfig } from "./config.js";

/**
 * Builds the Express app for Streamable HTTP mode, without binding a port.
 * Separated from index.ts so it can be constructed directly in tests — importing
 * index.ts itself would trigger its top-level main()/process.exit side effects.
 */
export function createHttpApp(httpConfig: HttpTransportConfig): Express {
  // Host-header DNS-rebinding protection is handled by createMcpExpressApp itself
  // (auto-enabled for 127.0.0.1/localhost/::1, the default). Origin validation is a
  // separate concern the SDK doesn't cover, so it's added below.
  const app = createMcpExpressApp({ host: httpConfig.host });

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !httpConfig.allowedOrigins.includes(origin)) {
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: `Origin not allowed: ${origin}` },
        id: null
      });
      return;
    }
    next();
  });

  app.post("/mcp", async (req, res) => {
    // A fresh server + transport per request: true statelessness, no shared state
    // across concurrent callers (the SDK's documented pattern for stateless mode).
    const server = createServer();
    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      res.on("close", () => {
        transport.close();
        void server.close();
      });
    } catch (err) {
      console.error("Error handling MCP request:", err);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null
        });
      }
    }
  });

  const methodNotAllowed = (
    _req: unknown,
    res: { status: (code: number) => { json: (body: unknown) => void } }
  ): void => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null
    });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  return app;
}
