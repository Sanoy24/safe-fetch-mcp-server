import type { CacheConfig, SafeFetchConfig } from "../config.js";
import { parseAndValidateUrl } from "./urlPolicy.js";
import { resolveAndPin } from "./resolveAndPin.js";
import {
  assertRedirectAllowed,
  fetchWithRedirects,
  SafeFetchError,
  type SafeFetchOptions,
  type SafeFetchResult
} from "./redirects.js";

/**
 * Opt-in, in-memory response cache (SAFE_FETCH_CACHE_TTL_MS > 0).
 *
 * The invariant: a cache hit must never be a way around the guard. Policy and DNS
 * can change between calls (different config, a host that now resolves somewhere
 * forbidden), so before serving a stored body, every URL in the stored redirect
 * chain is re-checked with the same URL policy, DNS/IP classification and
 * downgrade rule a live fetch would use. Only the network request is skipped.
 * A failed check throws exactly as a live fetch would; nothing stale is served.
 *
 * Bounded by entry count and total body bytes (LRU). Only complete 200 responses
 * are stored; `no-store` and `private` are honoured, as is `max-age` when it is
 * shorter than the configured TTL. Stale entries with an ETag or Last-Modified are
 * revalidated with a conditional request.
 */

interface CacheEntry {
  readonly result: SafeFetchResult;
  /** When the entry was stored or last revalidated. */
  readonly storedAt: number;
  readonly freshForMs: number;
}

const entries = new Map<string, CacheEntry>();
let totalBytes = 0;

/** Test helper: empties the process-wide cache. */
export function clearResponseCache(): void {
  entries.clear();
  totalBytes = 0;
}

export function isCacheEnabled(cfg: SafeFetchConfig): boolean {
  return (cfg.cache?.ttlMs ?? 0) > 0;
}

// The byte cap is part of the key: a smaller cap must never be answered with a
// larger body stored under a bigger one.
function cacheKey(url: string, cfg: SafeFetchConfig): string {
  return `${cfg.maxBytes} ${url}`;
}

function directives(cacheControl: string | undefined): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of (cacheControl ?? "").split(",")) {
    const [name, value] = part.trim().toLowerCase().split("=");
    if (name) map.set(name, value?.replace(/"/g, "") ?? "");
  }
  return map;
}

/** How long a response may be reused, or null if it must not be stored. */
function freshnessMs(result: SafeFetchResult, cache: CacheConfig): number | null {
  if (result.status !== 200 || result.truncated) return null;
  if (result.body.byteLength > cache.maxBytes) return null;
  const cc = directives(result.cacheControl);
  if (cc.has("no-store") || cc.has("private")) return null;
  if (cc.has("no-cache")) return 0; // store, but revalidate before every use
  const maxAge = Number(cc.get("max-age"));
  return Number.isFinite(maxAge) && maxAge >= 0
    ? Math.min(cache.ttlMs, maxAge * 1000)
    : cache.ttlMs;
}

function remove(key: string): void {
  const entry = entries.get(key);
  if (!entry) return;
  totalBytes -= entry.result.body.byteLength;
  entries.delete(key);
}

function store(
  key: string,
  result: SafeFetchResult,
  cache: CacheConfig,
  now: number
): void {
  remove(key);
  const freshForMs = freshnessMs(result, cache);
  if (freshForMs === null) return;
  entries.set(key, { result, storedAt: now, freshForMs });
  totalBytes += result.body.byteLength;
  // Map iteration order is insertion order, so the first key is least recently used.
  for (const oldest of entries.keys()) {
    if (entries.size <= cache.maxEntries && totalBytes <= cache.maxBytes) break;
    remove(oldest);
  }
}

function touch(key: string, entry: CacheEntry): void {
  entries.delete(key);
  entries.set(key, entry);
}

async function withDeadline<T>(work: Promise<T>, cfg: SafeFetchConfig): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new SafeFetchError(
            "TIMEOUT",
            `Refused: request timed out after ${cfg.timeoutMs}ms.`
          )
        ),
      cfg.timeoutMs
    );
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** Re-runs every guard check a live fetch of this chain would run, minus the request. */
async function assertChainStillAllowed(
  urlChain: readonly string[],
  cfg: SafeFetchConfig,
  options: SafeFetchOptions
): Promise<void> {
  let previous: URL | undefined;
  for (const hop of urlChain) {
    const url = parseAndValidateUrl(hop, cfg);
    await resolveAndPin(url.hostname, cfg.allowLocal, options.resolve);
    if (previous) assertRedirectAllowed(previous, url, cfg);
    previous = url;
  }
}

export async function fetchWithCache(
  rawUrl: string,
  cfg: SafeFetchConfig,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const cache = cfg.cache;
  if (!cache || cache.ttlMs <= 0) return fetchWithRedirects(rawUrl, cfg, options);

  const now = options.now ?? Date.now;
  // Policy-check the requested URL before even looking at the cache.
  const key = cacheKey(parseAndValidateUrl(rawUrl, cfg).toString(), cfg);
  const entry = entries.get(key);

  if (entry && now() - entry.storedAt <= entry.freshForMs) {
    await withDeadline(assertChainStillAllowed(entry.result.urlChain, cfg, options), cfg);
    touch(key, entry);
    return { ...entry.result, fromCache: true };
  }

  const cached = entry?.result;
  const canRevalidate = cached !== undefined && (cached.etag || cached.lastModified);
  const result = await fetchWithRedirects(
    rawUrl,
    cfg,
    canRevalidate
      ? {
          ...options,
          conditional: {
            url: cached.finalUrl,
            ...(cached.etag ? { etag: cached.etag } : {}),
            ...(cached.lastModified ? { lastModified: cached.lastModified } : {})
          }
        }
      : options
  );

  // 304 from the same final URL: the stored body is still current. The live
  // request just went through the full guard, so the chain is already re-checked.
  if (result.status === 304 && cached && result.finalUrl === cached.finalUrl) {
    const refreshed: SafeFetchResult = {
      ...cached,
      urlChain: result.urlChain,
      ...(result.etag ? { etag: result.etag } : {}),
      ...(result.lastModified ? { lastModified: result.lastModified } : {}),
      ...(result.cacheControl ? { cacheControl: result.cacheControl } : {})
    };
    store(key, refreshed, cache, now());
    return { ...refreshed, fromCache: true };
  }

  store(key, result, cache, now());
  return result;
}
