import * as http from "node:http";
import * as https from "node:https";
import type { SafeFetchConfig } from "../config.js";
import { parseAndValidateUrl } from "./urlPolicy.js";
import { resolveAndPin, type PinnedTarget, type Resolver } from "./resolveAndPin.js";

export class SafeFetchError extends Error {}

export interface SafeFetchResult {
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType: string;
  readonly body: Buffer;
  readonly truncated: boolean;
}

/** Test seams only — never exposed through the MCP tool. */
export interface SafeFetchOptions {
  readonly resolve?: Resolver;
}

interface RawResponse {
  readonly status: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
  readonly truncated: boolean;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function timeoutError(cfg: SafeFetchConfig): SafeFetchError {
  return new SafeFetchError(`Refused: request timed out after ${cfg.timeoutMs}ms.`);
}

/**
 * Settles with `promise`, or rejects with `onAbort()` as soon as `signal` aborts —
 * for work that can't be cancelled itself (dns.lookup), so the deadline still holds.
 */
function untilAborted<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  onAbort: () => Error
): Promise<T> {
  if (signal.aborted) return Promise.reject(onAbort());
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(onAbort());
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (err: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(err);
      }
    );
  });
}

function performPinnedRequest(
  url: URL,
  pinned: PinnedTarget,
  cfg: SafeFetchConfig,
  signal: AbortSignal
): Promise<RawResponse> {
  const client = url.protocol === "https:" ? https : http;
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;

  return new Promise((resolve, reject) => {
    let settled = false;
    const settleResolve = (value: RawResponse): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const settleReject = (err: Error): void => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const req = client.request(
      {
        protocol: url.protocol,
        host: pinned.hostname,
        servername: pinned.hostname,
        lookup: pinned.lookup,
        agent: false,
        port,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        // Aborting destroys the socket at any stage: connect, headers or body.
        signal,
        headers: {
          // url.host keeps a non-default port, as RFC 9110 requires.
          Host: url.host,
          "User-Agent": "safe-fetch-mcp-server"
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        let received = 0;

        res.on("data", (chunk: Buffer) => {
          received += chunk.length;
          if (received > cfg.maxBytes) {
            const overshoot = received - cfg.maxBytes;
            const allowed = chunk.length - overshoot;
            if (allowed > 0) chunks.push(chunk.subarray(0, allowed));
            settleResolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks),
              truncated: true
            });
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          settleResolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
            truncated: false
          });
        });

        res.on("error", (err) => {
          settleReject(
            signal.aborted
              ? timeoutError(cfg)
              : new SafeFetchError(`Refused: response stream error: ${err.message}`)
          );
        });

        // A socket torn down mid-body may close without "end" or "error".
        res.on("close", () => {
          if (!res.complete) {
            settleReject(
              signal.aborted
                ? timeoutError(cfg)
                : new SafeFetchError(
                    "Refused: connection closed before the response completed."
                  )
            );
          }
        });
      }
    );

    req.on("error", (err) => {
      settleReject(
        signal.aborted
          ? timeoutError(cfg)
          : new SafeFetchError(
              `Refused: request to "${pinned.hostname}" failed: ${err.message}`
            )
      );
    });

    req.end();
  });
}

/**
 * Fetches a URL, following redirects manually. Every hop — including the first —
 * goes through parseAndValidateUrl + resolveAndPin again, so a 302 to an internal
 * address is refused exactly like a direct request would be. This loop is the only
 * fetch path; do not add a second one (see CLAUDE.md).
 *
 * cfg.timeoutMs is ONE total deadline for the whole operation — DNS, connect,
 * headers and body, across every hop. A per-socket idle timer is not enough: a
 * server dripping a byte at a time would reset it forever.
 */
export async function fetchWithRedirects(
  rawUrl: string,
  cfg: SafeFetchConfig,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  const { signal } = controller;

  try {
    let currentUrl = rawUrl;
    let redirectCount = 0;

    for (;;) {
      const url = parseAndValidateUrl(currentUrl, cfg.allowlist);
      const pinned = await untilAborted(
        resolveAndPin(url.hostname, cfg.allowLocal, options.resolve),
        signal,
        () => timeoutError(cfg)
      );
      const response = await performPinnedRequest(url, pinned, cfg, signal);

      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.location;
        if (!location) {
          throw new SafeFetchError(
            `Refused: redirect response (${response.status}) had no Location header.`
          );
        }
        redirectCount += 1;
        if (redirectCount > cfg.maxRedirects) {
          throw new SafeFetchError(
            `Refused: exceeded maximum of ${cfg.maxRedirects} redirects.`
          );
        }
        currentUrl = new URL(location, url).toString();
        continue;
      }

      const contentTypeHeader = response.headers["content-type"];
      const contentType = Array.isArray(contentTypeHeader)
        ? (contentTypeHeader[0] ?? "application/octet-stream")
        : (contentTypeHeader ?? "application/octet-stream");

      return {
        status: response.status,
        finalUrl: url.toString(),
        contentType,
        body: response.body,
        truncated: response.truncated
      };
    }
  } finally {
    clearTimeout(timer);
  }
}
