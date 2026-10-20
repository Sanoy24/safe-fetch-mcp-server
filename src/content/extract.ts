import { parseHTML } from "linkedom";
import { Readability } from "@mozilla/readability";
import { baseType, decodeBody, htmlToMarkdown } from "./toMarkdown.js";

/**
 * Turns a fetched body into markdown plus page metadata.
 *
 * "main" (default) uses Mozilla Readability on a linkedom DOM to keep the article and
 * drop navigation, banners and footers. It was chosen by benchmark: ~46% fewer
 * characters across 14 real pages, with far less page chrome. Both libraries are pure
 * parsers with no network access, so this is never a second fetch path.
 *
 * Whenever extraction looks lossy it falls back to the full page, and says so:
 * the agent can always ask for extract: "full".
 */
export type ExtractMode = "main" | "full";
export type Extraction = "main" | "full" | "fallback-full" | "none";

/** Signals for the agent about how to treat the result. */
export const HINTS = [
  "suspicious-hidden-content-removed",
  "likely-requires-javascript"
] as const;
export type Hint = (typeof HINTS)[number];

export interface PageMetadata {
  title?: string;
  description?: string;
  byline?: string;
  lang?: string;
  canonicalUrl?: string;
  publishedAt?: string;
  siteName?: string;
}

export interface ExtractedContent {
  readonly markdown: string;
  readonly extraction: Extraction;
  readonly metadata: PageMetadata;
  readonly hints: Hint[];
}

/**
 * Bound on DOM size for reader-mode extraction. Real pages measured up to ~6.7k
 * elements. Enforced here because Readability's own maxElemsToParse relies on
 * getElementsByTagName("*"), which returns 0 under linkedom.
 */
export const MAX_ELEMENTS_TO_PARSE = 30_000;
const MAX_METADATA_CHARS = 300;
const SUBSTANTIAL_PAGE_CHARS = 1_000;
const MIN_MAIN_CHARS = 200;
const MIN_CODE_BLOCKS_TO_CHECK = 3;

// Metadata is page-controlled (untrusted): strip control characters, collapse
// whitespace and cap the length so it can't smuggle a wall of injected text.
function clean(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text === "" ? undefined : text.slice(0, MAX_METADATA_CHARS);
}

function httpUrl(
  value: string | null | undefined,
  base: string | undefined
): string | undefined {
  if (!value) return undefined;
  try {
    const url = base ? new URL(value, base) : new URL(value);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url.toString().slice(0, 2_000)
      : undefined;
  } catch {
    return undefined;
  }
}

function prune(metadata: PageMetadata): PageMetadata {
  return Object.fromEntries(
    Object.entries(metadata).filter(([, v]) => v !== undefined)
  ) as PageMetadata;
}

type Doc = ReturnType<typeof parseHTML>["document"];

function htmlMetadata(document: Doc, baseUrl: string | undefined): PageMetadata {
  const meta = (selector: string): string | null | undefined =>
    document.querySelector(selector)?.getAttribute("content");
  return {
    title:
      clean(document.querySelector("title")?.textContent) ??
      clean(meta('meta[property="og:title"]')),
    description:
      clean(meta('meta[name="description"]')) ??
      clean(meta('meta[property="og:description"]')),
    lang: clean(document.documentElement?.getAttribute("lang")),
    canonicalUrl: httpUrl(
      document.querySelector('link[rel="canonical"]')?.getAttribute("href"),
      baseUrl
    ),
    siteName: clean(meta('meta[property="og:site_name"]')),
    publishedAt:
      clean(meta('meta[property="article:published_time"]')) ??
      clean(document.querySelector("time[datetime]")?.getAttribute("datetime"))
  };
}

/** YAML front matter that server-rendered markdown (e.g. Cloudflare) may start with. */
function frontMatterMetadata(markdown: string): PageMetadata {
  const match = /^---\r?\n([\s\S]{0,4000}?)\r?\n---\r?\n/.exec(markdown);
  if (!match?.[1]) return {};
  const fields = new Map<string, string>();
  for (const line of match[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_]+):\s*(.*)$/.exec(line);
    if (kv?.[1] && kv[2] !== undefined) {
      fields.set(kv[1].toLowerCase(), kv[2].replace(/^["']|["']$/g, ""));
    }
  }
  return {
    title: clean(fields.get("title")),
    description: clean(fields.get("description"))
  };
}

function countCodeBlocks(html: string): number {
  return (html.match(/<pre[\s>]/gi) ?? []).length;
}

// Invisible characters used to hide or reorder text from human readers: zero-width
// spaces/joiners, bidi overrides and isolates, word joiners, and the BOM.
const INVISIBLE_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

function stripInvisible(text: string): string {
  return text.replace(INVISIBLE_CHARS, "");
}

const HIDDEN_SELECTOR = '[hidden], [aria-hidden="true"], template, input[type="hidden"]';
const HIDING_STYLE =
  /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:!important)?\s*(?:;|$)/i;

// Phrases typical of prompt injection. Ordinary pages hide plenty of text (menus,
// screen-reader labels), so the hint only fires when hidden text looks like it's
// addressed to an AI. It's a heuristic signal, not a filter: hidden content is
// removed either way.
const INJECTION_LIKE =
  /\b(?:ignore|disregard|forget|override)\b[^.]{0,40}\b(?:previous|prior|above|earlier|all|system)\b[^.]{0,20}\b(?:instructions?|prompts?|rules|messages?)\b|\byou are now\b|\bsystem prompt\b|\b(?:new|updated|hidden) instructions?\b|\b(?:as an|you are an?) (?:ai|assistant|language model)\b|<\/?(?:system|assistant|instructions?)>|\b(?:reveal|send|email|exfiltrate|leak)\b[^.]{0,40}\b(?:api[ _-]?keys?|passwords?|secrets?|tokens?|credentials?)\b/i;

/**
 * Removes elements a human reader can't see (threat-model row 25). Returns true if any
 * removed text looked like instructions aimed at an AI.
 */
function removeHiddenElements(document: Doc): boolean {
  const hidden = [
    ...document.querySelectorAll(HIDDEN_SELECTOR),
    ...[...document.querySelectorAll("[style]")].filter((el) =>
      HIDING_STYLE.test(el.getAttribute("style") ?? "")
    )
  ];
  let suspicious = false;
  for (const el of hidden) {
    if (!el.isConnected) continue; // already removed with a hidden ancestor
    if (INJECTION_LIKE.test(el.textContent ?? "")) suspicious = true;
    el.remove();
  }
  return suspicious;
}

const APP_MOUNT_SELECTOR =
  "#root, #app, #__next, #__nuxt, #svelte, [ng-app], [data-reactroot]";
const SPA_MAX_TEXT_CHARS = 250;

/**
 * True for an empty single-page-app shell: almost no visible text, plus an empty app
 * mount point or a <noscript> asking for JavaScript. Must run before scripts are removed.
 */
function looksLikeJavaScriptShell(document: Doc): boolean {
  const noscriptAsksForJs = [...document.querySelectorAll("noscript")].some((el) =>
    /javascript/i.test(el.textContent ?? "")
  );
  const emptyMount = [...document.querySelectorAll(APP_MOUNT_SELECTOR)].some(
    (el) => (el.textContent ?? "").trim() === ""
  );
  if (!noscriptAsksForJs && !emptyMount) return false;

  const clone = document.body?.cloneNode(true) as typeof document.body | undefined;
  if (!clone) return true;
  for (const el of [...clone.querySelectorAll("script, style, noscript, template")])
    el.remove();
  return (
    (clone.textContent ?? "").replace(/\s+/g, " ").trim().length < SPA_MAX_TEXT_CHARS
  );
}

export function extractContent(
  body: Buffer,
  contentType: string,
  mode: ExtractMode,
  baseUrl?: string
): ExtractedContent {
  const decoded = decodeBody(body, contentType);
  const type = baseType(contentType);

  if (type !== "text/html" && type !== "application/xhtml+xml") {
    const metadata = type === "text/markdown" ? frontMatterMetadata(decoded) : {};
    return {
      markdown: stripInvisible(decoded),
      extraction: "none",
      metadata: prune(metadata),
      hints: []
    };
  }

  const { document } = parseHTML(decoded);
  const metadata = htmlMetadata(document, baseUrl);
  const hints = new Set<Hint>();
  if (looksLikeJavaScriptShell(document)) hints.add("likely-requires-javascript");
  for (const el of [...document.querySelectorAll("script, style, noscript")]) el.remove();
  if (removeHiddenElements(document)) hints.add("suspicious-hidden-content-removed");

  // Everything below works from the cleaned DOM, so hidden content can't reach the
  // agent through either the main-content or the full-page path.
  const cleanedHtml = document.toString();
  const finish = (
    markdown: string,
    extraction: Extraction,
    meta: PageMetadata
  ): ExtractedContent => {
    return {
      markdown: stripInvisible(markdown),
      extraction,
      metadata: prune(meta),
      hints: [...hints]
    };
  };
  const full = (extraction: Extraction): ExtractedContent =>
    finish(htmlToMarkdown(cleanedHtml), extraction, metadata);

  if (mode === "full") return full("full");
  if (document.querySelectorAll("*").length > MAX_ELEMENTS_TO_PARSE) {
    return full("fallback-full");
  }

  const pageChars = (document.body?.textContent ?? "").replace(/\s+/g, " ").trim().length;
  const codeBlocksBefore = document.querySelectorAll("pre").length;

  let article: ReturnType<Readability["parse"]> = null;
  try {
    article = new Readability(
      document as unknown as ConstructorParameters<typeof Readability>[0],
      { maxElemsToParse: MAX_ELEMENTS_TO_PARSE }
    ).parse();
  } catch {
    article = null;
  }
  if (!article?.content) return full("fallback-full");

  // Safety net: prefer the noisy full page over silently losing content.
  const mainChars = (article.textContent ?? "").replace(/\s+/g, " ").trim().length;
  if (pageChars >= SUBSTANTIAL_PAGE_CHARS && mainChars < MIN_MAIN_CHARS) {
    return full("fallback-full");
  }
  if (
    codeBlocksBefore >= MIN_CODE_BLOCKS_TO_CHECK &&
    countCodeBlocks(article.content) < codeBlocksBefore / 2
  ) {
    return full("fallback-full");
  }

  let markdown = htmlToMarkdown(article.content);
  // Readability returns the title separately; restore it so the text stands alone.
  const title = clean(article.title);
  if (title && !markdown.trimStart().startsWith("#"))
    markdown = `# ${title}\n\n${markdown}`;

  return finish(markdown, "main", {
    ...metadata,
    byline: clean(article.byline),
    lang: metadata.lang ?? clean(article.lang),
    siteName: metadata.siteName ?? clean(article.siteName),
    publishedAt: metadata.publishedAt ?? clean(article.publishedTime),
    description: metadata.description ?? clean(article.excerpt)
  });
}
