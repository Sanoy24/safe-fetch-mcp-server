import { getConfig, type SafeFetchConfig } from "../config.js";
import { parseAndValidateUrl, UrlPolicyError } from "./urlPolicy.js";
import { resolveAndPin, ResolutionError } from "./resolveAndPin.js";
import {
  fetchWithRedirects,
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

/**
 * The single hardened fetch path. Every outbound request in this server — including
 * every redirect hop — must go through this function. Do not add a second fetch path.
 */
export async function safeFetch(
  rawUrl: string,
  cfg: SafeFetchConfig = getConfig(),
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  return fetchWithRedirects(rawUrl, cfg, options);
}
