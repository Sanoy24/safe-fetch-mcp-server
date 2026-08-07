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
