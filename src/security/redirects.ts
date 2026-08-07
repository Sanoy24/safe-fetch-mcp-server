import * as http from "node:http";
import * as https from "node:https";
import type { SafeFetchConfig } from "../config.js";
import { parseAndValidateUrl } from "./urlPolicy.js";
import { resolveAndPin, type PinnedTarget } from "./resolveAndPin.js";

export class SafeFetchError extends Error {}

export interface SafeFetchResult {
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType: string;
  readonly body: Buffer;
  readonly truncated: boolean;
}

interface RawResponse {
  readonly status: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
  readonly truncated: boolean;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function performPinnedRequest(
  url: URL,
  pinned: PinnedTarget,
  cfg: SafeFetchConfig
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
        timeout: cfg.timeoutMs,
        headers: {
          Host: pinned.hostname,
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
          settleReject(new SafeFetchError(`Refused: response stream error: ${err.message}`));
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      settleReject(
        new SafeFetchError(`Refused: request to "${pinned.hostname}" timed out after ${cfg.timeoutMs}ms.`)
      );
    });

    req.on("error", (err) => {
      settleReject(new SafeFetchError(`Refused: request to "${pinned.hostname}" failed: ${err.message}`));
    });

    req.end();
  });
}

/**
 * Fetches a URL, following redirects manually. Every hop — including the first —
 * goes through parseAndValidateUrl + resolveAndPin again, so a 302 to an internal
 * address is refused exactly like a direct request would be. This loop is the only
 * fetch path; do not add a second one (see CLAUDE.md).
 */
export async function fetchWithRedirects(
  rawUrl: string,
  cfg: SafeFetchConfig
): Promise<SafeFetchResult> {
  let currentUrl = rawUrl;
  let redirectCount = 0;

  for (;;) {
    const url = parseAndValidateUrl(currentUrl, cfg.allowlist);
    const pinned = await resolveAndPin(url.hostname, cfg.allowLocal);
    const response = await performPinnedRequest(url, pinned, cfg);

    if (REDIRECT_STATUSES.has(response.status)) {
      const location = response.headers.location;
      if (!location) {
        throw new SafeFetchError(
          `Refused: redirect response (${response.status}) had no Location header.`
        );
      }
      redirectCount += 1;
      if (redirectCount > cfg.maxRedirects) {
        throw new SafeFetchError(`Refused: exceeded maximum of ${cfg.maxRedirects} redirects.`);
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
}
