import { DEFAULT_USER_AGENT, type SafeFetchConfig } from "../config.js";
import { GuardError } from "./errors.js";
import { fetchWithRedirects, type SafeFetchOptions } from "./redirects.js";

/**
 * robots.txt (RFC 9309), checked when SAFE_FETCH_ROBOTS=respect. robots.txt is itself
 * attacker-controlled: it is fetched through the one guarded fetch path, can redirect
 * only where any other fetch could, and its parsed size and matching cost are bounded.
 */
interface Rule {
  readonly allow: boolean;
  /** Normalized pattern, without a trailing $. */
  readonly pattern: string;
  readonly anchored: boolean;
  /** Length of the original pattern, which decides the most specific match. */
  readonly specificity: number;
}

const MAX_ROBOTS_BYTES = 512_000; // RFC 9309 requires parsing at least 500 KiB
const ROBOTS_TIMEOUT_MS = 5_000;
const MAX_RULES = 5_000;
const MAX_PATTERN_CHARS = 1_024;
const MAX_MATCHED_PATH_CHARS = 8_192;
const CACHE_TTL_MS = 60 * 60 * 1000;
const MAX_CACHED_ORIGINS = 1_000;
const BYTE_ORDER_MARK = 0xfeff;

/** Decodes escaped unreserved characters and normalizes the rest, so equal paths compare equal. */
function normalize(value: string): string {
  return value
    .replace(/[^\x20-\x7e]+/g, (chars) => encodeURIComponent(chars))
    .replace(/%[0-9a-f]{2}/gi, (escape) => {
      const char = String.fromCharCode(Number.parseInt(escape.slice(1), 16));
      return /[A-Za-z0-9\-._~]/.test(char) ? char : escape.toUpperCase();
    });
}

function toRule(allow: boolean, rawPattern: string): Rule | null {
  if (rawPattern === "" || rawPattern.length > MAX_PATTERN_CHARS) return null;
  const anchored = rawPattern.endsWith("$");
  return {
    allow,
    pattern: normalize(anchored ? rawPattern.slice(0, -1) : rawPattern),
    anchored,
    specificity: rawPattern.length
  };
}

/** Keeps only the rules that apply to this crawler: its own group if any, otherwise `*`. */
export function parseRobots(rawText: string, productToken: string): readonly Rule[] {
  const text = rawText.charCodeAt(0) === BYTE_ORDER_MARK ? rawText.slice(1) : rawText;
  const token = productToken.toLowerCase();
  const own: Rule[] = [];
  const star: Rule[] = [];
  let hasOwnGroup = false;
  let current = { own: false, star: false };
  let collectingAgents = false;

  for (const rawLine of text.split(/\r\n|\r|\n/)) {
    const line = rawLine.split("#", 1)[0] ?? "";
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();

    if (key === "user-agent") {
      if (!collectingAgents) current = { own: false, star: false };
      collectingAgents = true;
      const agent = value.toLowerCase();
      if (agent === "*") current.star = true;
      else if (/^[a-z_-]+/.exec(agent)?.[0] === token) {
        current.own = true;
        hasOwnGroup = true;
      }
    } else if (key === "allow" || key === "disallow") {
      collectingAgents = false;
      const rule = toRule(key === "allow", value);
      if (!rule) continue;
      if (current.own && own.length < MAX_RULES) own.push(rule);
      if (current.star && star.length < MAX_RULES) star.push(rule);
    }
  }
  return hasOwnGroup ? own : star;
}

// Taking the leftmost match of each piece is enough, so there is no backtracking and no
// regular expression for a hostile pattern to blow up.
function matches(rule: Rule, path: string): boolean {
  const pieces = rule.pattern.split("*");
  if (pieces.length === 1) {
    return rule.anchored ? path === rule.pattern : path.startsWith(rule.pattern);
  }
  const first = pieces[0] ?? "";
  if (!path.startsWith(first)) return false;
  let position = first.length;
  for (const piece of pieces.slice(1, -1)) {
    const found = path.indexOf(piece, position);
    if (found === -1) return false;
    position = found + piece.length;
  }
  const last = pieces[pieces.length - 1] ?? "";
  if (rule.anchored) return path.length - last.length >= position && path.endsWith(last);
  return path.indexOf(last, position) !== -1;
}

/** The longest matching rule wins; on a tie, allow wins. No match means allowed. */
export function isPathAllowed(rules: readonly Rule[], rawPath: string): boolean {
  const path = normalize(rawPath.slice(0, MAX_MATCHED_PATH_CHARS));
  let best: Rule | undefined;
  for (const rule of rules) {
    if (!matches(rule, path)) continue;
    const moreSpecific = !best || rule.specificity > best.specificity;
    const tieWon = best && rule.specificity === best.specificity && rule.allow;
    if (moreSpecific || tieWon) best = rule;
  }
  return best?.allow ?? true;
}

/** The token robots.txt groups are matched against: the User-Agent's leading name. */
export function productToken(userAgent: string): string {
  return /^[A-Za-z_-]+/.exec(userAgent)?.[0] ?? "safe-fetch-mcp-server";
}

function unavailable(host: string): GuardError {
  return new GuardError(
    "ROBOTS_UNAVAILABLE",
    `Refused: could not read robots.txt on "${host}", so the site's rules are unknown. Try again later.`
  );
}

async function loadRules(
  url: URL,
  token: string,
  cfg: SafeFetchConfig,
  options: SafeFetchOptions
): Promise<readonly Rule[]> {
  try {
    const { status, body } = await fetchWithRedirects(
      `${url.origin}/robots.txt`,
      {
        ...cfg,
        maxBytes: Math.min(cfg.maxBytes, MAX_ROBOTS_BYTES),
        timeoutMs: Math.min(cfg.timeoutMs, ROBOTS_TIMEOUT_MS)
      },
      options.resolve ? { resolve: options.resolve } : {}
    );
    if (status === 429 || status >= 500) throw unavailable(url.hostname);
    return status >= 200 && status < 300
      ? parseRobots(body.toString("utf-8"), token)
      : [];
  } catch (err) {
    if (!(err instanceof GuardError)) throw err;
    if (err.code === "TIMEOUT" || err.code === "INVALID_RESPONSE") {
      throw unavailable(url.hostname);
    }
    // A robots.txt that redirects somewhere refused or dead is a bad file, not a verdict
    // on this page. A refused target was never contacted, and the page gets its own guard.
    // Failing on the first hop means the site itself is unreachable or refused: report that.
    const redirected = (err.urlChain?.length ?? 0) > 1;
    if (err.code === "REDIRECT_FAILED" || redirected) return [];
    throw err;
  }
}

interface CacheEntry {
  readonly rules: Promise<readonly Rule[]>;
  readonly expires: number;
}

const cache = new Map<string, CacheEntry>();

/** Test helper: empties the process-wide robots cache. */
export function clearRobotsCache(): void {
  cache.clear();
}

function rulesFor(
  url: URL,
  token: string,
  cfg: SafeFetchConfig,
  options: SafeFetchOptions
): Promise<readonly Rule[]> {
  const now = options.now?.() ?? Date.now();
  const key = `${token} ${url.origin}`;
  const cached = cache.get(key);
  if (cached && cached.expires > now) return cached.rules;

  // The promise is stored, so parallel fetches of one site share one robots.txt request.
  const rules = loadRules(url, token, cfg, options);
  cache.delete(key);
  cache.set(key, { rules, expires: now + CACHE_TTL_MS });
  for (const oldest of cache.keys()) {
    if (cache.size <= MAX_CACHED_ORIGINS) break;
    cache.delete(oldest);
  }
  // Failures aren't remembered: the next call asks again.
  rules.catch(() => {
    if (cache.get(key)?.rules === rules) cache.delete(key);
  });
  return rules;
}

/** Throws ROBOTS_DISALLOWED when robots.txt forbids this URL. Runs for every redirect hop. */
export async function assertRobotsAllow(
  url: URL,
  cfg: SafeFetchConfig,
  options: SafeFetchOptions
): Promise<void> {
  if (url.pathname === "/robots.txt") return;
  const token = productToken(cfg.userAgent ?? DEFAULT_USER_AGENT);
  const rules = await rulesFor(url, token, cfg, options);
  if (!isPathAllowed(rules, `${url.pathname}${url.search}`)) {
    throw new GuardError(
      "ROBOTS_DISALLOWED",
      `Refused: robots.txt on "${url.hostname}" disallows this URL for automated clients. ` +
        "This is the site owner's policy, so don't retry it another way. Tell the user."
    );
  }
}
