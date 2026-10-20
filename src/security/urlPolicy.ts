import type { SafeFetchConfig } from "../config.js";
import { GuardError } from "./errors.js";
import { hostMatches } from "./hostPatterns.js";

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);
const DEFAULT_PORTS: Readonly<Record<string, number>> = { "http:": 80, "https:": 443 };

/** Structural URL policy violations. Always POLICY_REJECTED. */
export class UrlPolicyError extends GuardError {
  constructor(message: string) {
    super("POLICY_REJECTED", message);
  }
}

export type UrlPolicy = Pick<
  SafeFetchConfig,
  "allowlist" | "denylist" | "httpsOnly" | "allowedPorts"
>;

/** The port a connection to `url` will actually use, including the scheme default. */
export function effectivePort(url: URL): number {
  return url.port ? Number(url.port) : (DEFAULT_PORTS[url.protocol] ?? 0);
}

/**
 * Structural checks that don't require DNS: scheme allowlist (and optional
 * HTTPS-only), userinfo rejection, and the optional host and port allowlists.
 * Does not touch the network. Runs on the first request and on every redirect hop.
 */
export function parseAndValidateUrl(rawUrl: string, policy: UrlPolicy): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UrlPolicyError(`Refused: "${rawUrl}" is not a valid absolute URL.`);
  }

  if (!ALLOWED_SCHEMES.has(url.protocol)) {
    throw new UrlPolicyError(
      `Refused: scheme "${url.protocol}" is not allowed. Only http and https are permitted.`
    );
  }

  if (policy.httpsOnly && url.protocol !== "https:") {
    throw new UrlPolicyError(
      "Refused: plain http:// is not allowed because SAFE_FETCH_HTTPS_ONLY is enabled. Use https://."
    );
  }

  if (url.username !== "" || url.password !== "") {
    throw new UrlPolicyError(
      "Refused: URLs with embedded credentials (user:pass@host) are not allowed."
    );
  }

  const allowedPorts = policy.allowedPorts ?? [];
  if (allowedPorts.length > 0) {
    const port = effectivePort(url);
    if (!allowedPorts.includes(port)) {
      throw new UrlPolicyError(
        `Refused: port ${port} is not in SAFE_FETCH_ALLOWED_PORTS (${allowedPorts.join(", ")}).`
      );
    }
  }

  const host = url.hostname.toLowerCase();
  // Deny wins over allow, so a broad allow pattern can carve out exceptions.
  if (hostMatches(host, policy.denylist ?? [])) {
    throw new UrlPolicyError(`Refused: host "${host}" is on SAFE_FETCH_DENYLIST.`);
  }
  if (policy.allowlist.length > 0 && !hostMatches(host, policy.allowlist)) {
    throw new UrlPolicyError(`Refused: host "${host}" is not in SAFE_FETCH_ALLOWLIST.`);
  }

  return url;
}
