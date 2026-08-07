export interface SafeFetchConfig {
  allowLocal: boolean;
  allowlist: readonly string[];
  maxBytes: number;
  timeoutMs: number;
  maxRedirects: number;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value.toLowerCase() === "true";
}

function parseIntEnv(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parsePort(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= 65535 ? parsed : fallback;
}

function parseAllowlist(value: string | undefined): readonly string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host.length > 0);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SafeFetchConfig {
  return {
    allowLocal: parseBoolean(env["SAFE_FETCH_ALLOW_LOCAL"], false),
    allowlist: parseAllowlist(env["SAFE_FETCH_ALLOWLIST"]),
    maxBytes: parseIntEnv(env["SAFE_FETCH_MAX_BYTES"], 5_000_000),
    timeoutMs: parseIntEnv(env["SAFE_FETCH_TIMEOUT_MS"], 10_000),
    maxRedirects: parseIntEnv(env["SAFE_FETCH_MAX_REDIRECTS"], 5)
  };
}

export const config: SafeFetchConfig = loadConfig();

export interface HttpTransportConfig {
  readonly host: string;
  readonly port: number;
  /**
   * Origins allowed to send a browser-style Origin header. Defaults to empty,
   * meaning NO Origin is trusted — legitimate MCP clients (CLI bridges,
   * server-to-server callers) don't send one, so any request that does is refused.
   * This is the Origin-validation half of DNS-rebinding protection; Host-header
   * validation is handled separately by the SDK's createMcpExpressApp().
   */
  readonly allowedOrigins: readonly string[];
}

export function loadHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpTransportConfig {
  return {
    host: env["HOST"] ?? "127.0.0.1",
    port: parsePort(env["PORT"], 3000),
    allowedOrigins: parseAllowlist(env["SAFE_FETCH_ALLOWED_ORIGINS"])
  };
}
