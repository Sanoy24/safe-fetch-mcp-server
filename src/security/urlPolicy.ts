const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

export class UrlPolicyError extends Error {}

/**
 * Structural checks that don't require DNS: scheme allowlist, userinfo rejection,
 * and (if configured) a host allowlist. Does not touch the network.
 */
export function parseAndValidateUrl(
  rawUrl: string,
  allowlist: readonly string[]
): URL {
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

  if (url.username !== "" || url.password !== "") {
    throw new UrlPolicyError(
      "Refused: URLs with embedded credentials (user:pass@host) are not allowed."
    );
  }

  if (allowlist.length > 0) {
    const host = url.hostname.toLowerCase();
    if (!allowlist.includes(host)) {
      throw new UrlPolicyError(
        `Refused: host "${host}" is not in SAFE_FETCH_ALLOWLIST.`
      );
    }
  }

  return url;
}
