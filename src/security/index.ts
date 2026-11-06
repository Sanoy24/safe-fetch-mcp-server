import { getConfig, type SafeFetchConfig } from "../config.js";
import { parseAndValidateUrl, UrlPolicyError } from "./urlPolicy.js";
import { resolveAndPin, ResolutionError } from "./resolveAndPin.js";
import {
  assertChainStillAllowed,
  fetchWithCache,
  withDeadline
} from "./responseCache.js";
import { assertRobotsAllow } from "./robots.js";
import {
  SafeFetchError,
  type SafeFetchOptions,
  type SafeFetchResult
} from "./redirects.js";

export { UrlPolicyError, ResolutionError, SafeFetchError };
export {
  GuardError,
  isRetryable,
  FETCH_ERROR_CODES,
  type FetchErrorCode
} from "./errors.js";
export type { SafeFetchResult, SafeFetchConfig, SafeFetchOptions };

/**
 * Validates a URL against policy + DNS/IP checks without fetching it. Throws
 * (UrlPolicyError | ResolutionError) on any violation. Used for static checks and
 * as the first hop of safeFetch.
 */
export async function assertSafeUrl(
  rawUrl: string,
  cfg: SafeFetchConfig = getConfig()
): Promise<URL> {
  const url = parseAndValidateUrl(rawUrl, cfg);
  await resolveAndPin(url.hostname, cfg.allowLocal);
  return url;
}

function withPoliteness(
  cfg: SafeFetchConfig,
  options: SafeFetchOptions
): SafeFetchOptions {
  return cfg.robots === "respect"
    ? { ...options, checkHop: (url) => assertRobotsAllow(url, cfg, options) }
    : options;
}

/**
 * For anything served without a request, such as a page snapshot: runs every check a live
 * fetch of this redirect chain would run. Throws exactly as that fetch would.
 */
export async function assertChainAllowed(
  urlChain: readonly string[],
  cfg: SafeFetchConfig,
  options: SafeFetchOptions = {}
): Promise<void> {
  await withDeadline(
    assertChainStillAllowed(urlChain, cfg, withPoliteness(cfg, options)),
    cfg
  );
}

/**
 * The single hardened fetch path. Every outbound request in this server — including
 * every redirect hop — must go through this function. Do not add a second fetch path.
 */
export async function safeFetch(
  rawUrl: string,
  cfg: SafeFetchConfig = getConfig(),
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  // The optional cache wraps the single fetch path; it never makes requests itself
  // and re-runs the guard on every hit (see responseCache.ts).
  return fetchWithCache(rawUrl, cfg, withPoliteness(cfg, options));
}
