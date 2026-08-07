import TurndownService from "turndown";

const turndownService = new TurndownService({
  headingStyle: "atx",
  codeBlockStyle: "fenced"
});
// Turndown only skips *converting* unknown elements — it still emits their text
// content. script/style/noscript text is never document content, so drop it.
turndownService.remove(["script", "style", "noscript"]);

const TEXTUAL_TYPE_PREFIXES = [
  "text/",
  "application/json",
  "application/xml",
  "application/xhtml+xml"
];

function baseType(contentType: string): string {
  return contentType.split(";")[0]?.trim().toLowerCase() ?? "";
}

export function isTextualContentType(contentType: string): boolean {
  const base = baseType(contentType);
  return TEXTUAL_TYPE_PREFIXES.some((prefix) => base.startsWith(prefix));
}

/**
 * Converts an HTML body to clean markdown. Non-HTML textual content is returned
 * as-is (turndown only makes sense for HTML). Callers are responsible for checking
 * isTextualContentType before calling this — binary content should never reach it.
 */
export function toMarkdown(body: Buffer, contentType: string): string {
  const base = baseType(contentType);
  const text = body.toString("utf-8");

  if (base === "text/html" || base === "application/xhtml+xml") {
    return turndownService.turndown(text);
  }

  return text;
}
