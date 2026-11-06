import { GuardError } from "../security/errors.js";

/**
 * Reads part of a page instead of all of it: one JSON value, one markdown section, or the
 * list of headings. Works on text already fetched and cleaned. Error messages never quote
 * the page, because errors aren't framed as untrusted data.
 */
export interface Heading {
  readonly level: number;
  readonly title: string;
  /** Offset of the heading line in the text, usable as start_index. */
  readonly start: number;
}

const MAX_HEADING_LINE_CHARS = 500;
const FENCE = /^ {0,3}(`{3,}|~{3,})/;
const ATX_HEADING = /^ {0,3}(#{1,6})(?:[ \t]+(.*))?$/;
const SETEXT_UNDERLINE = /^ {0,3}(=+|-+)[ \t]*$/;
// Lines that are something else, so an underline below them isn't a heading.
const NOT_A_SETEXT_TITLE = /^ {0,3}(?:[-*+>|]|\d+[.)]\s|#{1,6}(?:\s|$))/;

function notFound(message: string): GuardError {
  return new GuardError("SELECTION_NOT_FOUND", message);
}

function cleanTitle(raw: string): string {
  return raw
    .replace(/[ \t]+#+[ \t]*$/, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[*_`]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/** Markdown headings outside code fences. Linear in the text's length. */
export function parseHeadings(text: string): Heading[] {
  const headings: Heading[] = [];
  let position = 0;
  let fence: string | null = null;
  let previous: { line: string; start: number } | null = null;

  for (const rawLine of text.split("\n")) {
    const start = position;
    position += rawLine.length + 1;
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;

    const marker = FENCE.exec(line)?.[1];
    if (fence !== null) {
      const closes =
        marker !== undefined &&
        marker[0] === fence[0] &&
        marker.length >= fence.length &&
        line.trim() === marker;
      if (closes) fence = null;
      previous = null;
      continue;
    }
    if (marker !== undefined) {
      fence = marker;
      previous = null;
      continue;
    }
    if (line.length > MAX_HEADING_LINE_CHARS) {
      previous = null;
      continue;
    }

    const atx = ATX_HEADING.exec(line);
    if (atx) {
      const title = cleanTitle(atx[2] ?? "");
      if (title) headings.push({ level: atx[1]?.length ?? 1, title, start });
      previous = null;
      continue;
    }

    const underline = SETEXT_UNDERLINE.exec(line);
    if (underline && previous) {
      const title = cleanTitle(previous.line);
      if (title) {
        headings.push({
          level: underline[1]?.startsWith("=") ? 1 : 2,
          title,
          start: previous.start
        });
      }
      previous = null;
      continue;
    }

    previous =
      line.trim() !== "" && !NOT_A_SETEXT_TITLE.test(line) ? { line, start } : null;
  }
  return headings;
}

const comparable = (title: string): string => title.toLowerCase();

/** An exact title wins, then a title starting with the query, then one containing it. */
export function selectSection(text: string, query: string): string {
  const headings = parseHeadings(text);
  const wanted = comparable(cleanTitle(query));
  const found =
    wanted === ""
      ? undefined
      : (headings.find((h) => comparable(h.title) === wanted) ??
        headings.find((h) => comparable(h.title).startsWith(wanted)) ??
        headings.find((h) => comparable(h.title).includes(wanted)));
  if (!found) {
    throw notFound(
      "Refused: no heading on this page matches that section. Call fetch_url with outline: true to list the headings."
    );
  }
  const next = headings.find((h) => h.start > found.start && h.level <= found.level);
  return text.slice(found.start, next?.start).trimEnd();
}

export function renderOutline(text: string): string {
  const lines = parseHeadings(text).map(
    (h) => `${"  ".repeat(h.level - 1)}- ${h.title} [start_index=${h.start}]`
  );
  return lines.length > 0 ? lines.join("\n") : "(no headings found)";
}

/**
 * The value at an RFC 6901 JSON Pointer: strings as they are, anything else as compact
 * JSON. Compact on purpose: indenting deeply nested input grows quadratically.
 */
export function selectJson(text: string, pointer: string): string {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw notFound(
      "Refused: json_pointer needs a JSON response, and this response isn't valid JSON."
    );
  }

  const missing = notFound(
    "Refused: nothing in this JSON response is at that json_pointer. Call fetch_url without it to see the document's structure."
  );
  for (const rawToken of pointer.split("/").slice(1)) {
    const token = rawToken.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(value)) {
      if (!/^(0|[1-9]\d*)$/.test(token) || Number(token) >= value.length) throw missing;
      value = value[Number(token)];
    } else if (
      value !== null &&
      typeof value === "object" &&
      Object.hasOwn(value, token)
    ) {
      value = (value as Record<string, unknown>)[token];
    } else {
      throw missing;
    }
  }

  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    // Nesting too deep for the serializer's recursion.
    throw new GuardError(
      "PROCESSING_LIMIT",
      "Refused: that JSON value is nested too deeply to return. Try a more specific json_pointer."
    );
  }
}
