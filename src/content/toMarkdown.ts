import TurndownService from "turndown";
import { parseHTML } from "linkedom";

const turndownService = new TurndownService({
  headingStyle: "atx",
  codeBlockStyle: "fenced"
});
// Turndown only skips *converting* unknown elements — it still emits their text
// content. script/style/noscript text is never document content, so drop it.
turndownService.remove(["script", "style", "noscript"]);

const TEXTUAL_TYPES = new Set([
  "application/json",
  "application/xml",
  "application/xhtml+xml",
  "application/javascript",
  "application/ecmascript"
]);

export function baseType(contentType: string): string {
  return contentType.split(";")[0]?.trim().toLowerCase() ?? "";
}

/** text/*, JSON, XML, JavaScript, and any structured-syntax `+json` / `+xml` type. */
export function isTextualContentType(contentType: string): boolean {
  const base = baseType(contentType);
  return (
    base.startsWith("text/") ||
    TEXTUAL_TYPES.has(base) ||
    base.endsWith("+json") ||
    base.endsWith("+xml")
  );
}

function charsetOf(contentType: string): string | undefined {
  return /;\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(contentType)?.[1];
}

/**
 * Decodes a body using the Content-Type charset, falling back to UTF-8 when the
 * charset is missing or unknown. Never throws: malformed bytes become U+FFFD.
 */
export function decodeBody(body: Buffer, contentType: string): string {
  const charset = charsetOf(contentType);
  if (charset) {
    try {
      return new TextDecoder(charset).decode(body);
    } catch {
      // Unknown label (RangeError) — fall through to UTF-8.
    }
  }
  return new TextDecoder("utf-8").decode(body);
}

/**
 * Converts an HTML body to clean markdown. Non-HTML textual content is returned
 * decoded but otherwise as-is (turndown only makes sense for HTML). Callers are
 * responsible for checking isTextualContentType first — binary content should
 * never reach it.
 */
// Turndown's cost grows with the square of its output (1 MB took 5 s, 2 MB took 18 s), so
// large pages are converted in batches split at block-level boundaries.
const BATCH_MIN_CHARS = 100_000;
const BATCH_TARGET_CHARS = 32_000;
const MAX_FLATTEN_DEPTH = 32;
// Containers that only separate blocks in markdown, so removing them changes nothing.
const FLATTENABLE = new Set(["HTML", "BODY", "DIV", "MAIN", "ARTICLE", "SECTION"]);
const BLOCK_TAGS = new Set(
  "ADDRESS ARTICLE ASIDE BLOCKQUOTE BODY DETAILS DIALOG DD DIV DL DT FIELDSET FIGCAPTION FIGURE FOOTER FORM H1 H2 H3 H4 H5 H6 HEADER HGROUP HR LI MAIN NAV OL P PRE SECTION TABLE UL".split(
    " "
  )
);

interface HtmlNode {
  readonly nodeType: number;
  readonly tagName?: string;
  readonly childNodes: Iterable<HtmlNode>;
  toString(): string;
}

/** Splits a node into block-level HTML pieces, grouping inline runs so they stay together. */
function blockPieces(node: HtmlNode, depth: number, pieces: string[]): void {
  let inlineRun = "";
  const flushInline = (): void => {
    if (inlineRun.trim() !== "") pieces.push(`<div>${inlineRun}</div>`);
    inlineRun = "";
  };
  for (const child of node.childNodes) {
    const tag = child.tagName ?? "";
    if (tag === "HEAD") continue;
    if (child.nodeType === 1 && BLOCK_TAGS.has(tag)) {
      flushInline();
      const html = child.toString();
      if (
        html.length > BATCH_TARGET_CHARS &&
        FLATTENABLE.has(tag) &&
        depth < MAX_FLATTEN_DEPTH
      ) {
        blockPieces(child, depth + 1, pieces);
      } else {
        pieces.push(html);
      }
    } else if (child.nodeType === 1 || child.nodeType === 3) {
      inlineRun += child.toString();
    }
  }
  flushInline();
}

/** Converts an HTML string (a whole page or an extracted fragment) to markdown. */
export function htmlToMarkdown(html: string): string {
  if (html.length < BATCH_MIN_CHARS) return turndownService.turndown(html);

  const isDocument = /<html[\s>]/i.test(html.slice(0, 2_000));
  const { document } = parseHTML(isDocument ? html : `<html><body>${html}</body></html>`);
  const pieces: string[] = [];
  const title = document.querySelector("head title")?.toString();
  if (title) pieces.push(`<div>${title}</div>`);
  // Not document.body: HTML5 lets pages omit <body>, and linkedom doesn't infer it.
  blockPieces(document.documentElement as unknown as HtmlNode, 0, pieces);
  if (pieces.length === 0) return turndownService.turndown(html);

  const parts: string[] = [];
  let batch = "";
  const flush = (): void => {
    const markdown = batch === "" ? "" : turndownService.turndown(batch);
    if (markdown !== "") parts.push(markdown);
    batch = "";
  };
  for (const piece of pieces) {
    batch += piece;
    if (batch.length >= BATCH_TARGET_CHARS) flush();
  }
  flush();
  return parts.join("\n\n");
}

export function toMarkdown(body: Buffer, contentType: string): string {
  const base = baseType(contentType);
  const text = decodeBody(body, contentType);

  if (base === "text/html" || base === "application/xhtml+xml") {
    return turndownService.turndown(text);
  }

  return text;
}
