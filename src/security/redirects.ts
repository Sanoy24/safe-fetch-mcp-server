import * as http from "node:http";
import * as https from "node:https";
import { isIP } from "node:net";
import * as zlib from "node:zlib";
import { Transform, type Readable, type TransformCallback } from "node:stream";
import type { SafeFetchConfig } from "../config.js";
import { effectivePort, parseAndValidateUrl, UrlPolicyError } from "./urlPolicy.js";
import { resolveAndPin, type PinnedTarget, type Resolver } from "./resolveAndPin.js";
import { GuardError } from "./errors.js";

export class SafeFetchError extends GuardError {}

export interface SafeFetchResult {
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType: string;
  readonly body: Buffer;
  readonly truncated: boolean;
  /** Every URL requested, in order; the last one is finalUrl. */
  readonly urlChain: readonly string[];
  /** True when the body came from the response cache. */
  readonly fromCache?: boolean;
  /** Cache validators and directives from the final response, if present. */
  readonly etag?: string;
  readonly lastModified?: string;
  readonly cacheControl?: string;
  /** Token count the site reported for its markdown (x-markdown-tokens), if any. */
  readonly markdownTokens?: number;
}

/**
 * Conditional-request validators. Sent only on the hop whose URL equals `url`
 * (the cached final URL), so an ETag never leaks to a different origin.
 */
export interface ConditionalRequest {
  readonly url: string;
  readonly etag?: string;
  readonly lastModified?: string;
}

/** Internal options — never exposed through the MCP tool. */
export interface SafeFetchOptions {
  /** Test seam: replaces DNS resolution. */
  readonly resolve?: Resolver;
  /** Used by the response cache to revalidate a stale entry. */
  readonly conditional?: ConditionalRequest;
  /** Test seam: the cache's clock. */
  readonly now?: () => number;
}

interface RawResponse {
  readonly status: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
  readonly truncated: boolean;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// Markdown content negotiation: sites that support it (Cloudflare "Markdown for Agents",
// Vercel, HackMD, ...) return server-rendered markdown; everyone else falls back to HTML
// or whatever they serve. */* keeps every server answering.
const ACCEPT =
  "text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.9, text/plain;q=0.8, application/json;q=0.8, */*;q=0.5";

// Compression saves bandwidth; the byte cap is enforced on the DECOMPRESSED stream, so
// a decompression bomb stops at SAFE_FETCH_MAX_BYTES (threat-model row 23). zstd is
// left out because not every supported Node version can decode it.
const ACCEPT_ENCODING = "gzip, br, deflate";

/**
 * "deflate" is zlib-wrapped per the spec, but some servers send raw deflate. Look at the
 * first two bytes (RFC 1950 header check) and pick the matching inflater.
 */
function createDeflateDecoder(): Transform {
  let inner: zlib.Inflate | zlib.InflateRaw | undefined;
  const decoder = new Transform({
    transform(chunk: Buffer, _enc: BufferEncoding, done: TransformCallback): void {
      if (!inner) {
        const b0 = chunk[0] ?? 0;
        const b1 = chunk[1] ?? 0;
        const zlibWrapped = (b0 & 0x0f) === 8 && ((b0 << 8) | b1) % 31 === 0;
        inner = zlibWrapped ? zlib.createInflate() : zlib.createInflateRaw();
        inner.on("data", (out: Buffer) => decoder.push(out));
        inner.on("error", (err) => decoder.destroy(err));
      }
      inner.write(chunk, () => done());
    },
    flush(done: TransformCallback): void {
      if (!inner) return done();
      inner.once("end", () => done());
      inner.end();
    }
  });
  return decoder;
}

/** A decoder for the response's Content-Encoding, null for none, or undefined if unsupported. */
function decoderFor(contentEncoding: string | undefined): Transform | null | undefined {
  const encoding = (contentEncoding ?? "").trim().toLowerCase();
  if (encoding === "" || encoding === "identity") return null;
  if (encoding === "gzip" || encoding === "x-gzip") return zlib.createGunzip();
  if (encoding === "br") return zlib.createBrotliDecompress();
  if (encoding === "deflate") return createDeflateDecoder();
  return undefined;
}

function timeoutError(cfg: SafeFetchConfig): SafeFetchError {
  return new SafeFetchError(
    "TIMEOUT",
    `Refused: request timed out after ${cfg.timeoutMs}ms.`
  );
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
  signal: AbortSignal,
  extraHeaders: Readonly<Record<string, string>>
): Promise<RawResponse> {
  const client = url.protocol === "https:" ? https : http;
  const port = effectivePort(url);
  // RFC 6066: SNI carries hostnames only, never IP literals.
  const bareHost = pinned.hostname.replace(/^\[|\]$/g, "");
  const servername = isIP(bareHost) === 0 ? pinned.hostname : undefined;

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
        ...(servername !== undefined ? { servername } : {}),
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
          "User-Agent": "safe-fetch-mcp-server",
          Accept: ACCEPT,
          "Accept-Encoding": ACCEPT_ENCODING,
          ...extraHeaders
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        let received = 0;

        const decoder = decoderFor(firstHeader(res.headers["content-encoding"]));
        if (decoder === undefined) {
          settleReject(
            new SafeFetchError(
              "INVALID_RESPONSE",
              "Refused: the response used a content encoding this server doesn't support.",
              {
                cause: `content-encoding=${firstHeader(res.headers["content-encoding"])}`
              }
            )
          );
          req.destroy();
          return;
        }
        const body: Readable = decoder ? res.pipe(decoder) : res;
        if (decoder) {
          decoder.on("error", (err) => {
            settleReject(
              signal.aborted
                ? timeoutError(cfg)
                : new SafeFetchError(
                    "INVALID_RESPONSE",
                    "Refused: the response body could not be decompressed.",
                    { cause: err.message }
                  )
            );
            req.destroy();
          });
        }

        // Counts DECOMPRESSED bytes, so the cap holds against decompression bombs.
        body.on("data", (chunk: Buffer) => {
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
            if (decoder) decoder.destroy();
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });

        body.on("end", () => {
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
              : new SafeFetchError(
                  "CONNECTION_FAILED",
                  `Refused: the connection to "${pinned.hostname}" failed while reading the response.`,
                  { cause: err.message }
                )
          );
        });

        // A socket torn down mid-body may close without "end" or "error".
        res.on("close", () => {
          if (!res.complete) {
            settleReject(
              signal.aborted
                ? timeoutError(cfg)
                : new SafeFetchError(
                    "CONNECTION_FAILED",
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
              "CONNECTION_FAILED",
              `Refused: could not connect to "${pinned.hostname}".`,
              {
                cause: err.message
              }
            )
      );
    });

    req.end();
  });
}

/**
 * Per-hop rule on top of the URL policy: an https:// page may not redirect to
 * plain http:// unless SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE is set. A downgrade
 * exposes the follow-up request, and the content returned, to network tampering.
 */
export function assertRedirectAllowed(from: URL, to: URL, cfg: SafeFetchConfig): void {
  if (from.protocol === "https:" && to.protocol === "http:" && !cfg.allowHttpsDowngrade) {
    throw new UrlPolicyError(
      "Refused: an https:// page redirected to plain http://. Set SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE=true to allow this."
    );
  }
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function conditionalHeaders(
  url: URL,
  conditional: ConditionalRequest | undefined
): Record<string, string> {
  if (!conditional || conditional.url !== url.toString()) return {};
  const headers: Record<string, string> = {};
  if (conditional.etag) headers["If-None-Match"] = conditional.etag;
  if (conditional.lastModified) headers["If-Modified-Since"] = conditional.lastModified;
  return headers;
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
    const urlChain: string[] = [];

    for (;;) {
      const url = parseAndValidateUrl(currentUrl, cfg);
      urlChain.push(url.toString());
      const pinned = await untilAborted(
        resolveAndPin(url.hostname, cfg.allowLocal, options.resolve),
        signal,
        () => timeoutError(cfg)
      );
      const response = await performPinnedRequest(
        url,
        pinned,
        cfg,
        signal,
        conditionalHeaders(url, options.conditional)
      );

      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.location;
        if (!location) {
          throw new SafeFetchError(
            "REDIRECT_FAILED",
            `Refused: redirect response (${response.status}) had no Location header.`
          );
        }
        redirectCount += 1;
        if (redirectCount > cfg.maxRedirects) {
          throw new SafeFetchError(
            "REDIRECT_FAILED",
            `Refused: exceeded maximum of ${cfg.maxRedirects} redirects.`
          );
        }
        let next: URL;
        try {
          next = new URL(location, url);
        } catch {
          throw new SafeFetchError(
            "REDIRECT_FAILED",
            "Refused: redirect response had an invalid Location header."
          );
        }
        assertRedirectAllowed(url, next, cfg);
        currentUrl = next.toString();
        continue;
      }

      const contentType =
        firstHeader(response.headers["content-type"]) ?? "application/octet-stream";
      const etag = firstHeader(response.headers.etag);
      const lastModified = firstHeader(response.headers["last-modified"]);
      const cacheControl = firstHeader(response.headers["cache-control"]);
      const tokensHeader = firstHeader(response.headers["x-markdown-tokens"])?.trim();
      const markdownTokens =
        tokensHeader !== undefined && /^\d{1,9}$/.test(tokensHeader)
          ? Number(tokensHeader)
          : undefined;

      return {
        status: response.status,
        finalUrl: url.toString(),
        urlChain,
        contentType,
        body: response.body,
        truncated: response.truncated,
        ...(etag !== undefined ? { etag } : {}),
        ...(lastModified !== undefined ? { lastModified } : {}),
        ...(cacheControl !== undefined ? { cacheControl } : {}),
        ...(markdownTokens !== undefined ? { markdownTokens } : {})
      };
    }
  } finally {
    clearTimeout(timer);
  }
}
