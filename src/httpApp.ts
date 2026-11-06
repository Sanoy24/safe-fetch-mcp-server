import { createHash, timingSafeEqual } from "node:crypto";
import type { Express, RequestHandler } from "express";
import { rateLimit } from "express-rate-limit";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { createServer } from "./server.js";
import type { HttpTransportConfig } from "./config.js";

const CORS_ALLOWED_HEADERS = "Content-Type, Accept, Mcp-Protocol-Version, Authorization";
const LOCALHOST_HOSTNAMES = ["127.0.0.1", "localhost", "[::1]"];

// Comparing digests keeps the check constant-time and independent of the token's length.
function tokenMatches(header: string | undefined, expected: string): boolean {
  const presented = /^Bearer +(\S+)$/i.exec(header ?? "")?.[1];
  if (presented === undefined) return false;
  const digest = (value: string): Buffer => createHash("sha256").update(value).digest();
  return timingSafeEqual(digest(presented), digest(expected));
}

function requireToken(expected: string | undefined): RequestHandler {
  return (req, res, next) => {
    if (expected === undefined || tokenMatches(req.headers.authorization, expected)) {
      next();
      return;
    }
    res.setHeader("WWW-Authenticate", "Bearer");
    res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Missing or invalid bearer token." },
      id: null
    });
  };
}

/**
 * Builds the Express app for Streamable HTTP mode, without binding a port.
 * Separated from index.ts so it can be constructed directly in tests — importing
 * index.ts itself would trigger its top-level main()/process.exit side effects.
 */
export function createHttpApp(httpConfig: HttpTransportConfig): Express {
  // Host-header DNS-rebinding protection (CVE-2025-66414/66416,
  // CVE-2026-35568/35577 class): passed explicitly rather than relying on
  // createMcpExpressApp's implicit host-based auto-detection, so the allow-list
  // stays in force even if HOST is ever pointed at something other than the
  // localhost default.
  const allowedHosts = [
    ...new Set([httpConfig.host, ...LOCALHOST_HOSTNAMES, ...httpConfig.allowedHosts])
  ];
  const app = createMcpExpressApp({ host: httpConfig.host, allowedHosts });
  // The rate limiter keys on req.ip. Hops are counted, never "trust everything", so a
  // client can't choose its own IP with a forged X-Forwarded-For.
  if (httpConfig.trustProxyHops > 0) app.set("trust proxy", httpConfig.trustProxyHops);

  app.use(
    rateLimit({
      windowMs: httpConfig.rateLimitWindowMs,
      limit: httpConfig.rateLimitMax,
      standardHeaders: true,
      legacyHeaders: false,
      handler: (_req, res) => {
        res.status(429).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Too many requests." },
          id: null
        });
      }
    })
  );

  // Origin validation is a separate DNS-rebinding-adjacent concern the SDK
  // doesn't cover on its own.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin === undefined) {
      next();
      return;
    }
    // Origins are compared case-insensitively: browsers always send a lowercase
    // Origin, but non-browser callers aren't guaranteed to canonicalize casing.
    if (!httpConfig.allowedOrigins.includes(origin.toLowerCase())) {
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Origin not allowed." },
        id: null
      });
      return;
    }
    // Origin is explicitly allowlisted: echo it back so the browser accepts the
    // response too, not just the preflight (see the OPTIONS handler below).
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    next();
  });

  app.options("/mcp", (_req, res) => {
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", CORS_ALLOWED_HEADERS);
    res.status(204).end();
  });

  // After the rate limiter, so guesses count against it, and after OPTIONS, because
  // browsers send preflights without credentials.
  app.post("/mcp", requireToken(httpConfig.httpToken), async (req, res) => {
    // A fresh server + transport per request: true statelessness, no shared state
    // across concurrent callers (the SDK's documented pattern for stateless mode).
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    // Registered before handleRequest: a response can finish inside it, and a listener
    // added afterwards would miss the event and leak this server+transport pair.
    let closed = false;
    const cleanUp = (): void => {
      if (closed) return;
      closed = true;
      void transport.close();
      void server.close();
    };
    res.on("close", cleanUp);
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("Error handling MCP request:", err);
      cleanUp();
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null
        });
      }
    }
  });

  const respondMethodNotAllowed = (res: {
    status: (code: number) => { json: (body: unknown) => void };
  }): void => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null
    });
  };
  app.get("/mcp", (_req, res) => respondMethodNotAllowed(res));
  app.delete("/mcp", (_req, res) => respondMethodNotAllowed(res));

  return app;
}
