import TurndownService from "turndown";

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

function baseType(contentType: string): string {
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
export function toMarkdown(body: Buffer, contentType: string): string {
  const base = baseType(contentType);
  const text = decodeBody(body, contentType);

  if (base === "text/html" || base === "application/xhtml+xml") {
    return turndownService.turndown(text);
  }

  return text;
}
