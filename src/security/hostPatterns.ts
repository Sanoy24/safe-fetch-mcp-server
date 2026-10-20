import { ConfigError } from "../configError.js";

/**
 * Host patterns for SAFE_FETCH_ALLOWLIST / SAFE_FETCH_DENYLIST:
 *   - "docs.python.org" matches exactly that host;
 *   - "*.python.org" matches any subdomain at any depth, but not "python.org" itself.
 * Entries are normalized like WHATWG URL hostnames (lowercase, punycode for Unicode),
 * and a trailing dot is ignored on both sides, so config and URLs compare like for like.
 *
 * These are policy filters on the URL's hostname only. They never replace the
 * resolved-IP checks, which always run as well.
 */

const WILDCARD_PREFIX = "*.";

function stripTrailingDot(host: string): string {
  return host.endsWith(".") ? host.slice(0, -1) : host;
}

function normalizeHost(name: string, raw: string): string {
  // A bare hostname, or a bracketed IPv6 literal. No scheme, port, path, userinfo or
  // stray wildcard. The URL parser below does the real validation.
  const isIPv6Literal = /^\[[0-9a-f:.]+\]$/iu.test(raw);
  if (!isIPv6Literal && !/^[^\s/:?#@*\\[\]]+$/u.test(raw)) {
    throw new ConfigError(`${name}: "${raw}" is not a hostname or *.hostname pattern.`);
  }
  let hostname: string;
  try {
    hostname = new URL(`http://${raw}/`).hostname;
  } catch {
    throw new ConfigError(`${name}: "${raw}" is not a valid hostname.`);
  }
  const host = stripTrailingDot(hostname);
  if (host === "") throw new ConfigError(`${name}: "${raw}" is not a valid hostname.`);
  return host;
}

/** Parses a comma-separated pattern list from the environment. Throws ConfigError. */
export function parseHostPatterns(name: string, value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) =>
      entry.startsWith(WILDCARD_PREFIX)
        ? WILDCARD_PREFIX + normalizeHost(name, entry.slice(WILDCARD_PREFIX.length))
        : normalizeHost(name, entry)
    );
}

/** True if `hostname` (as produced by the URL parser) matches any pattern. */
export function hostMatches(hostname: string, patterns: readonly string[]): boolean {
  const host = stripTrailingDot(hostname.toLowerCase());
  return patterns.some((raw) => {
    const pattern = stripTrailingDot(raw.toLowerCase());
    if (pattern.startsWith(WILDCARD_PREFIX)) {
      const suffix = pattern.slice(WILDCARD_PREFIX.length);
      return host.endsWith(`.${suffix}`);
    }
    return host === pattern;
  });
}
