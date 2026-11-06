export interface CacheConfig {
  /** How long a response is reused. 0 disables the cache (default). */
  readonly ttlMs: number;
  readonly maxEntries: number;
  /** Upper bound on the total body bytes held in memory. */
  readonly maxBytes: number;
}

export interface SafeFetchConfig {
  allowLocal: boolean;
  /** Host patterns ("host" or "*.host"); when non-empty, only these hosts are allowed. */
  allowlist: readonly string[];
  /** Host patterns that are always refused; wins over the allowlist. */
  denylist?: readonly string[];
  maxBytes: number;
  timeoutMs: number;
  maxRedirects: number;
  // Optional egress tightening. Undefined means the documented default.
  /** Refuse plain http:// URLs and hops. Default false. */
  httpsOnly?: boolean;
  /** Follow https:// → http:// redirects. Default false (refused). */
  allowHttpsDowngrade?: boolean;
  /** Destination ports allowed. Empty or undefined allows any port. */
  allowedPorts?: readonly number[];
  /** Response cache. Undefined or ttlMs 0 disables it. */
  cache?: CacheConfig;
  /** Audit-log line format on stderr. Default "text". */
  logFormat?: "text" | "json";
  /** Also expose the reference server's `fetch` tool and prompt. Default false. */
  compatFetchTool?: boolean;
}

import { ConfigError } from "./configError.js";
import { parseHostPatterns } from "./security/hostPatterns.js";

export { ConfigError };

// Invalid values fail startup instead of silently falling back to a default: a
// typo in a security setting should be loud, not quietly "fixed".

function parseBoolean(
  name: string,
  value: string | undefined,
  fallback: boolean
): boolean {
  if (value === undefined || value.trim() === "") return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true" || normalized === "1") return true;
  if (normalized === "false" || normalized === "0") return false;
  throw new ConfigError(`${name} must be "true" or "false" (got "${value}").`);
}

function parseIntEnv(
  name: string,
  value: string | undefined,
  fallback: number,
  { min = 1, max = Number.MAX_SAFE_INTEGER }: { min?: number; max?: number } = {}
): number {
  if (value === undefined || value.trim() === "") return fallback;
  const trimmed = value.trim();
  const parsed = /^\d+$/.test(trimmed) ? Number(trimmed) : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    const range =
      max === Number.MAX_SAFE_INTEGER
        ? min === 1
          ? "a positive whole number"
          : `a whole number of at least ${min}`
        : `a whole number between ${min} and ${max}`;
    throw new ConfigError(`${name} must be ${range} (got "${value}").`);
  }
  return parsed;
}

function parseList(value: string | undefined): readonly string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
}

function parsePorts(name: string, value: string | undefined): readonly number[] {
  return parseList(value).map((entry) =>
    parseIntEnv(name, entry, 0, { min: 1, max: 65_535 })
  );
}

function parseLogFormat(value: string | undefined): "text" | "json" {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (normalized === "" || normalized === "text") return "text";
  if (normalized === "json") return "json";
  throw new ConfigError(
    `SAFE_FETCH_LOG_FORMAT must be "text" or "json" (got "${value}").`
  );
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SafeFetchConfig {
  return {
    allowLocal: parseBoolean(
      "SAFE_FETCH_ALLOW_LOCAL",
      env["SAFE_FETCH_ALLOW_LOCAL"],
      false
    ),
    allowlist: parseHostPatterns("SAFE_FETCH_ALLOWLIST", env["SAFE_FETCH_ALLOWLIST"]),
    denylist: parseHostPatterns("SAFE_FETCH_DENYLIST", env["SAFE_FETCH_DENYLIST"]),
    maxBytes: parseIntEnv("SAFE_FETCH_MAX_BYTES", env["SAFE_FETCH_MAX_BYTES"], 5_000_000),
    timeoutMs: parseIntEnv("SAFE_FETCH_TIMEOUT_MS", env["SAFE_FETCH_TIMEOUT_MS"], 10_000),
    maxRedirects: parseIntEnv(
      "SAFE_FETCH_MAX_REDIRECTS",
      env["SAFE_FETCH_MAX_REDIRECTS"],
      5,
      { min: 0, max: 20 }
    ),
    httpsOnly: parseBoolean("SAFE_FETCH_HTTPS_ONLY", env["SAFE_FETCH_HTTPS_ONLY"], false),
    allowHttpsDowngrade: parseBoolean(
      "SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE",
      env["SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE"],
      false
    ),
    allowedPorts: parsePorts("SAFE_FETCH_ALLOWED_PORTS", env["SAFE_FETCH_ALLOWED_PORTS"]),
    cache: {
      ttlMs: parseIntEnv("SAFE_FETCH_CACHE_TTL_MS", env["SAFE_FETCH_CACHE_TTL_MS"], 0, {
        min: 0
      }),
      maxEntries: parseIntEnv(
        "SAFE_FETCH_CACHE_MAX_ENTRIES",
        env["SAFE_FETCH_CACHE_MAX_ENTRIES"],
        100
      ),
      maxBytes: parseIntEnv(
        "SAFE_FETCH_CACHE_MAX_BYTES",
        env["SAFE_FETCH_CACHE_MAX_BYTES"],
        20_000_000
      )
    },
    logFormat: parseLogFormat(env["SAFE_FETCH_LOG_FORMAT"]),
    compatFetchTool: parseBoolean(
      "SAFE_FETCH_COMPAT_TOOL",
      env["SAFE_FETCH_COMPAT_TOOL"],
      false
    )
  };
}

let cachedConfig: SafeFetchConfig | undefined;

/** Process-wide config, loaded from the environment on first use. */
export function getConfig(): SafeFetchConfig {
  cachedConfig ??= loadConfig();
  return cachedConfig;
}

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
  /** Extra hostnames accepted in the Host header, such as a reverse proxy's public name. */
  readonly allowedHosts: readonly string[];
  /** When set, POST /mcp requires this bearer token. */
  readonly httpToken?: string;
  /** Reverse proxies in front of this server, for finding the client IP. 0 trusts none. */
  readonly trustProxyHops: number;
  /** Requests allowed per window, per client IP. */
  readonly rateLimitMax: number;
  readonly rateLimitWindowMs: number;
}

const MIN_TOKEN_LENGTH = 16;
const HOSTNAME_ENTRY = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)$/;

// Never echoes the value: it's a secret, even when it's an invalid one.
function parseHttpToken(value: string | undefined): string | undefined {
  const token = value?.trim();
  if (!token) return undefined;
  if (token.length < MIN_TOKEN_LENGTH || /\s/.test(token)) {
    throw new ConfigError(
      `SAFE_FETCH_HTTP_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters with no spaces. ` +
        "Generate one with: openssl rand -hex 32"
    );
  }
  return token;
}

function parseAllowedHosts(value: string | undefined): readonly string[] {
  const hosts = parseList(value);
  for (const host of hosts) {
    if (!HOSTNAME_ENTRY.test(host)) {
      throw new ConfigError(
        `SAFE_FETCH_ALLOWED_HOSTS takes hostnames only, with no scheme, port or wildcard (got "${host}").`
      );
    }
  }
  return hosts;
}

export function loadHttpConfig(
  env: NodeJS.ProcessEnv = process.env
): HttpTransportConfig {
  const host = env["HOST"]?.trim() || "127.0.0.1";
  const httpToken = parseHttpToken(env["SAFE_FETCH_HTTP_TOKEN"]);
  const insecure = parseBoolean(
    "SAFE_FETCH_HTTP_INSECURE",
    env["SAFE_FETCH_HTTP_INSECURE"],
    false
  );
  if (!isLoopbackHost(host) && httpToken === undefined && !insecure) {
    throw new ConfigError(
      `HOST is ${host}, which isn't loopback, and no SAFE_FETCH_HTTP_TOKEN is set. Anyone who ` +
        "could reach this address could make this server fetch URLs. Set SAFE_FETCH_HTTP_TOKEN, " +
        "or set SAFE_FETCH_HTTP_INSECURE=true if your own proxy handles authentication."
    );
  }
  return {
    host,
    ...(httpToken !== undefined ? { httpToken } : {}),
    allowedHosts: parseAllowedHosts(env["SAFE_FETCH_ALLOWED_HOSTS"]),
    trustProxyHops: parseIntEnv(
      "SAFE_FETCH_TRUST_PROXY",
      env["SAFE_FETCH_TRUST_PROXY"],
      0,
      {
        min: 0,
        max: 10
      }
    ),
    port: parseIntEnv("PORT", env["PORT"], 3000, { max: 65_535 }),
    allowedOrigins: parseList(env["SAFE_FETCH_ALLOWED_ORIGINS"]),
    rateLimitMax: parseIntEnv(
      "SAFE_FETCH_RATE_LIMIT_MAX",
      env["SAFE_FETCH_RATE_LIMIT_MAX"],
      60
    ),
    rateLimitWindowMs: parseIntEnv(
      "SAFE_FETCH_RATE_LIMIT_WINDOW_MS",
      env["SAFE_FETCH_RATE_LIMIT_WINDOW_MS"],
      60_000
    )
  };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.toLowerCase());
}
