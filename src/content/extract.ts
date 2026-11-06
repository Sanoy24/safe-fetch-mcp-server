import { parseHTML } from "linkedom";
import { Readability } from "@mozilla/readability";
import { baseType, decodeBody, htmlToMarkdown } from "./toMarkdown.js";
import {
  hasSmuggledText,
  INJECTION_LIKE,
  sanitizeMarkdown,
  stripInvisible,
  type ImageMode
} from "./sanitize.js";

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
  "suspicious-metadata-removed",
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
  const text = stripInvisible(value)
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

/** Metadata sits outside the content markers, so instruction-like values don't get through. */
function screenMetadata(metadata: PageMetadata, hints: Set<Hint>): PageMetadata {
  const kept = Object.entries(prune(metadata)).filter(([, value]) => {
    if (!INJECTION_LIKE.test(value as string)) return true;
    hints.add("suspicious-metadata-removed");
    return false;
  });
  return Object.fromEntries(kept) as PageMetadata;
}

type Doc = ReturnType<typeof parseHTML>["document"];

/** The page content. HTML5 lets pages omit <body>, and linkedom doesn't infer it. */
function contentRoot(document: Doc): Doc["documentElement"] {
  const body = document.body;
  return body && body.childNodes.length > 0 ? body : document.documentElement;
}

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

const FRONT_MATTER = /^---\r?\n([\s\S]{0,4000}?)\r?\n---[ \t]*(?:\r?\n)+/;

/** YAML front matter that server-rendered markdown (e.g. Cloudflare) may start with. */
function frontMatterMetadata(markdown: string): PageMetadata {
  const match = FRONT_MATTER.exec(markdown);
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

const HIDDEN_SELECTOR = '[hidden], [aria-hidden="true"], template, input[type="hidden"]';
// Off-screen and zero-size tricks: common ways to hide text from people but not parsers.
const FAR_OFFSCREEN_PX = -999;
const SOFT_HIDDEN_MAX_SHARE = 0.5;
const VISUALLY_HIDDEN_CLASSES = ".sr-only, .visually-hidden, .screen-reader-text";
const RESPONSIVE_CLASS = /(?:^|\s)(?:\S+:\S+|d-\w+-\S+)(?:\s|$)/;

function declarations(style: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of style.split(";")) {
    const i = part.indexOf(":");
    if (i > 0) {
      map.set(
        part.slice(0, i).trim().toLowerCase(),
        part
          .slice(i + 1)
          .replace(/!important/i, "")
          .trim()
          .toLowerCase()
      );
    }
  }
  return map;
}

const isZero = (value: string | undefined): boolean =>
  value !== undefined && /^[-+]?0*\.?0+(?:[a-z%]+)?$/.test(value);
const isFarOffscreen = (value: string | undefined): boolean =>
  value !== undefined && Number.parseFloat(value) <= FAR_OFFSCREEN_PX;

/** Definite: the browser certainly won't show this. */
function styleCertainlyHides(style: string): boolean {
  const d = declarations(style);
  return (
    d.get("display") === "none" ||
    d.get("visibility") === "hidden" ||
    d.get("visibility") === "collapse"
  );
}

/** Heuristic: very likely hidden, though some are used for fade-ins or similar effects. */
function styleProbablyHides(style: string): boolean {
  const d = declarations(style);
  const positioned = d.get("position") === "absolute" || d.get("position") === "fixed";
  const clipped = d.get("overflow") === "hidden";
  const opacity = d.get("opacity");
  return (
    (opacity !== undefined && Number.parseFloat(opacity) <= 0.01) ||
    isZero(d.get("font-size")) ||
    d.get("color") === "transparent" ||
    isFarOffscreen(d.get("text-indent")) ||
    (positioned &&
      (isFarOffscreen(d.get("left")) ||
        isFarOffscreen(d.get("top")) ||
        isFarOffscreen(d.get("right")) ||
        isFarOffscreen(d.get("bottom")))) ||
    (clipped &&
      (isZero(d.get("height")) ||
        isZero(d.get("width")) ||
        isZero(d.get("max-height")) ||
        isZero(d.get("max-width")))) ||
    /^rect\(\s*0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?\s*\)$/.test(
      d.get("clip") ?? ""
    ) ||
    /^(?:inset\(\s*(?:50|100)%|circle\(\s*0)/.test(d.get("clip-path") ?? "") ||
    /^scale\(\s*0\s*\)$/.test(d.get("transform") ?? "")
  );
}

/**
 * Selectors from the page's own <style> rules that hide content. Only top-level rules with
 * simple class or id selectors: @media rules (print, small screens) and compound selectors
 * depend on context a parser doesn't have.
 */
function hidingSelectors(document: Doc): string[] {
  const selectors: string[] = [];
  for (const el of [...document.querySelectorAll("style")]) {
    const css = (el.textContent ?? "").replace(/\/\*[\s\S]*?\*\//g, "");
    let depth = 0;
    let topLevel = "";
    for (const ch of css) {
      if (ch === "{") depth += 1;
      if (depth <= 1) topLevel += ch;
      if (ch === "}") depth -= 1;
    }
    // Drop @-rule blocks, whose nested bodies were collapsed above.
    const rules = topLevel.replace(/@[^{};]*(?:\{[^}]*\}|;)/g, "");
    for (const rule of rules.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const body = rule[2] ?? "";
      if (!styleCertainlyHides(body) && !styleProbablyHides(body)) continue;
      for (const raw of (rule[1] ?? "").split(",")) {
        const selector = raw.trim();
        if (
          /^[a-z][\w-]*$/i.test(selector) === false &&
          /^(?:[a-z][\w-]*)?(?:[.#][\w-]+)+$/i.test(selector)
        ) {
          selectors.push(selector);
        }
      }
    }
  }
  return selectors;
}

/**
 * Removes elements a human reader can't see (threat-model row 25). Returns true if any
 * removed text looked like instructions aimed at an AI. Best effort: without a real
 * browser some tricks (e.g. text the same colour as its background) can't be detected.
 */
function removeHiddenElements(document: Doc): boolean {
  let suspicious = false;
  const remove = (el: Doc["documentElement"]): void => {
    if (!el.isConnected) return; // already removed with a hidden ancestor
    if (INJECTION_LIKE.test(el.textContent ?? "")) suspicious = true;
    el.remove();
  };

  const styled = [...document.querySelectorAll("[style]")];
  const stylesheetRules = hidingSelectors(document);
  for (const el of [...document.querySelectorAll("style")]) el.remove();

  for (const el of [...document.querySelectorAll(HIDDEN_SELECTOR)]) remove(el);
  for (const el of styled) {
    if (styleCertainlyHides(el.getAttribute("style") ?? "")) remove(el);
  }

  // Heuristics can misfire (a page fading in from opacity 0 looks hidden), so they
  // never get to remove most of a page.
  const candidates = [
    ...styled.filter((el) => styleProbablyHides(el.getAttribute("style") ?? "")),
    ...[...document.querySelectorAll(VISUALLY_HIDDEN_CLASSES)],
    ...[...document.querySelectorAll(".hidden, .d-none")].filter(
      (el) => !RESPONSIVE_CLASS.test(el.getAttribute("class") ?? "")
    ),
    ...stylesheetRules.flatMap((selector) => [...document.querySelectorAll(selector)])
  ].filter((el) => el.isConnected);
  const pageChars = (contentRoot(document).textContent ?? "").length;
  const candidateChars = candidates.reduce(
    (n, el) => n + (el.textContent ?? "").length,
    0
  );
  if (candidateChars <= pageChars * SOFT_HIDDEN_MAX_SHARE) {
    for (const el of candidates) remove(el);
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

  const clone = contentRoot(document).cloneNode(true) as Doc["documentElement"];
  for (const el of [...clone.querySelectorAll("head, title")]) el.remove();
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
  baseUrl?: string,
  images: ImageMode = "alt"
): ExtractedContent {
  const decoded = decodeBody(body, contentType);
  const type = baseType(contentType);
  const hints = new Set<Hint>();
  if (hasSmuggledText(decoded)) hints.add("suspicious-hidden-content-removed");

  if (decoded.trim() === "") {
    return { markdown: "", extraction: "none", metadata: {}, hints: [] };
  }

  if (type === "text/markdown") {
    const metadata = screenMetadata(frontMatterMetadata(decoded), hints);
    const { text, suspicious } = sanitizeMarkdown(
      decoded.replace(FRONT_MATTER, ""),
      images
    );
    if (suspicious) hints.add("suspicious-hidden-content-removed");
    return {
      markdown: stripInvisible(text),
      extraction: "none",
      metadata,
      hints: [...hints]
    };
  }

  if (type !== "text/html" && type !== "application/xhtml+xml") {
    return {
      markdown: stripInvisible(decoded),
      extraction: "none",
      metadata: {},
      hints: [...hints]
    };
  }

  // linkedom needs a root element; fragments and bare text don't always have one.
  const { document } = parseHTML(
    /<html[\s>]/i.test(decoded) ? decoded : `<html><body>${decoded}</body></html>`
  );
  const metadata = htmlMetadata(document, baseUrl);
  if (looksLikeJavaScriptShell(document)) hints.add("likely-requires-javascript");
  for (const el of [...document.querySelectorAll("script, noscript")]) el.remove();
  if (removeHiddenElements(document)) hints.add("suspicious-hidden-content-removed");

  // Everything below works from the cleaned DOM, so hidden content can't reach the
  // agent through either the main-content or the full-page path.
  const cleanedHtml = document.toString();
  const finish = (
    markdown: string,
    extraction: Extraction,
    meta: PageMetadata
  ): ExtractedContent => {
    const screened = screenMetadata(meta, hints);
    return {
      markdown: stripInvisible(markdown),
      extraction,
      metadata: screened,
      hints: [...hints]
    };
  };
  const full = (extraction: Extraction): ExtractedContent =>
    finish(htmlToMarkdown(cleanedHtml, images), extraction, metadata);

  if (mode === "full") return full("full");
  if (document.querySelectorAll("*").length > MAX_ELEMENTS_TO_PARSE) {
    return full("fallback-full");
  }

  const pageChars = (contentRoot(document).textContent ?? "")
    .replace(/\s+/g, " ")
    .trim().length;
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

  let markdown = htmlToMarkdown(article.content, images);
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
