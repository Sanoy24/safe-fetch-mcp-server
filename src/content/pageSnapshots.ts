import type { SafeFetchConfig } from "../config.js";
import type { Hint, PageMetadata } from "./extract.js";

/**
 * Short-lived copies of converted pages, so that reading a long page in chunks reads one
 * consistent version instead of downloading it again for every chunk. Holds converted
 * text only, never credentials: this server sends none, so every caller would get the
 * same public content. Serving one still goes through the guard (see fetchUrl.ts).
 */
export interface PageSnapshot {
  readonly text: string;
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType: string;
  readonly bytes: number;
  readonly truncated: boolean;
  readonly extraction: "main" | "full" | "fallback-full" | "none";
  readonly hints: readonly Hint[];
  readonly metadata: PageMetadata;
  readonly markdownTokens?: number;
  readonly urlChain: readonly string[];
}

const MAX_SNAPSHOTS = 50;
const MAX_TOTAL_CHARS = 50_000_000;

interface Entry {
  readonly page: PageSnapshot;
  readonly expires: number;
}

const entries = new Map<string, Entry>();
let totalChars = 0;

/** Test helper: empties the process-wide store. */
export function clearPageSnapshots(): void {
  entries.clear();
  totalChars = 0;
}

export function dropSnapshot(key: string): void {
  const entry = entries.get(key);
  if (!entry) return;
  totalChars -= entry.page.text.length;
  entries.delete(key);
}

export function getSnapshot(
  key: string,
  now: number = Date.now()
): PageSnapshot | undefined {
  const entry = entries.get(key);
  if (!entry) return undefined;
  if (entry.expires <= now) {
    dropSnapshot(key);
    return undefined;
  }
  // Map order is insertion order, so re-inserting marks it most recently used.
  entries.delete(key);
  entries.set(key, entry);
  return entry.page;
}

export function saveSnapshot(
  key: string,
  page: PageSnapshot,
  cfg: Pick<SafeFetchConfig, "snapshotTtlMs">,
  now: number = Date.now()
): void {
  dropSnapshot(key);
  const ttlMs = cfg.snapshotTtlMs ?? 0;
  if (ttlMs <= 0 || page.text.length > MAX_TOTAL_CHARS) return;
  entries.set(key, { page, expires: now + ttlMs });
  totalChars += page.text.length;
  for (const oldest of entries.keys()) {
    if (entries.size <= MAX_SNAPSHOTS && totalChars <= MAX_TOTAL_CHARS) break;
    dropSnapshot(oldest);
  }
}
