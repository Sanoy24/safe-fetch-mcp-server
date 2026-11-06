import type { SafeFetchConfig } from "../config.js";

/**
 * Caps outbound requests, overall and per host, so an agent loop can't hammer one site or
 * tie up the network. A slot is held only for one hop's request, never while waiting for
 * anything else, so a robots.txt lookup or a redirect can't deadlock against its own page.
 * Waiting counts against the caller's total deadline.
 */
export const DEFAULT_MAX_CONCURRENT = 16;
export const DEFAULT_MAX_PER_HOST = 4;

export type ReleaseSlot = () => void;

interface Waiter {
  readonly host: string;
  readonly maxConcurrent: number;
  readonly maxPerHost: number;
  readonly grant: () => void;
}

let active = 0;
const activePerHost = new Map<string, number>();
const waiting: Waiter[] = [];

function hasRoom(host: string, maxConcurrent: number, maxPerHost: number): boolean {
  return active < maxConcurrent && (activePerHost.get(host) ?? 0) < maxPerHost;
}

function take(host: string): ReleaseSlot {
  active += 1;
  activePerHost.set(host, (activePerHost.get(host) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    active -= 1;
    const remaining = (activePerHost.get(host) ?? 1) - 1;
    if (remaining === 0) activePerHost.delete(host);
    else activePerHost.set(host, remaining);
    grantWaiting();
  };
}

// First come, first served among those with room: a busy host doesn't hold up other hosts.
function grantWaiting(): void {
  for (let i = 0; i < waiting.length;) {
    const waiter = waiting[i] as Waiter;
    if (hasRoom(waiter.host, waiter.maxConcurrent, waiter.maxPerHost)) {
      waiting.splice(i, 1);
      waiter.grant();
    } else {
      i += 1;
    }
  }
}

/** Waits for a slot, or rejects with onAbort() as soon as the deadline passes. */
export function acquireSlot(
  rawHost: string,
  cfg: SafeFetchConfig,
  signal: AbortSignal,
  onAbort: () => Error
): Promise<ReleaseSlot> {
  if (signal.aborted) return Promise.reject(onAbort());
  const host = rawHost.toLowerCase();
  const maxConcurrent = cfg.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
  const maxPerHost = cfg.maxPerHost ?? DEFAULT_MAX_PER_HOST;
  if (hasRoom(host, maxConcurrent, maxPerHost)) return Promise.resolve(take(host));

  return new Promise<ReleaseSlot>((resolve, reject) => {
    const waiter: Waiter = {
      host,
      maxConcurrent,
      maxPerHost,
      grant: () => {
        signal.removeEventListener("abort", abort);
        resolve(take(host));
      }
    };
    const abort = (): void => {
      waiting.splice(waiting.indexOf(waiter), 1);
      reject(onAbort());
    };
    signal.addEventListener("abort", abort, { once: true });
    waiting.push(waiter);
  });
}
