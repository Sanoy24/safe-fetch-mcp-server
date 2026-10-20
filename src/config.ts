export interface CacheConfig {
  /** How long a response is reused. 0 disables the cache (default). */
  readonly ttlMs: number;
  readonly maxEntries: number;
  /** Upper bound on the total body bytes held in memory. */
  readonly maxBytes: number;
}

export interface SafeFetchConfig {
  allowLocal: boolean;
  allowlist: readonly string[];
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

/** Thrown for an invalid environment variable. The message names the variable. */
export class ConfigError extends Error {}

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
    allowlist: parseList(env["SAFE_FETCH_ALLOWLIST"]),
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
  /** Requests allowed per window, per client IP. */
  readonly rateLimitMax: number;
  readonly rateLimitWindowMs: number;
}

export function loadHttpConfig(
  env: NodeJS.ProcessEnv = process.env
): HttpTransportConfig {
  return {
    host: env["HOST"]?.trim() || "127.0.0.1",
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
