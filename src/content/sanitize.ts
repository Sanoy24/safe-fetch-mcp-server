/**
 * Cleaning for page-controlled text before it reaches the agent (threat-model rows 25, 27).
 * Best effort by nature: it removes the common channels for hiding text from a human
 * reader. Treat all fetched content as untrusted regardless.
 */
export type ImageMode = "alt" | "keep";

// Phrases typical of prompt injection. Ordinary pages hide plenty of text (menus,
// screen-reader labels), so hints only fire when hidden text looks like it's addressed
// to an AI. It's a heuristic signal, not a filter: hidden content is removed either way.
export const INJECTION_LIKE =
  /\b(?:ignore|disregard|forget|override)\b[^.]{0,40}\b(?:previous|prior|above|earlier|all|system)\b[^.]{0,20}\b(?:instructions?|prompts?|rules|messages?)\b|\byou are now\b|\bsystem prompt\b|\b(?:new|updated|hidden) instructions?\b|\b(?:as an|you are an?) (?:ai|assistant|language model)\b|<\/?(?:system|assistant|instructions?)>|\b(?:reveal|send|email|exfiltrate|leak)\b[^.]{0,40}\b(?:api[ _-]?keys?|passwords?|secrets?|tokens?|credentials?)\b/i;

const JOINER_SCRIPTS =
  "\\p{Script=Arabic}\\p{Script=Syriac}\\p{Script=Devanagari}\\p{Script=Bengali}\\p{Script=Gurmukhi}\\p{Script=Gujarati}\\p{Script=Oriya}\\p{Script=Tamil}\\p{Script=Telugu}\\p{Script=Kannada}\\p{Script=Malayalam}\\p{Script=Sinhala}\\p{Script=Myanmar}\\p{Script=Khmer}\\p{Script=Tibetan}";

// Alternatives before the final class are legitimate uses to keep: flag emoji tag
// sequences, emoji joiners and variation selectors, and joiners inside scripts that
// need them. Everything in the final class is invisible and removed.
const INVISIBLE = new RegExp(
  "(" +
    "\\u{1F3F4}[\\u{E0030}-\\u{E0039}\\u{E0061}-\\u{E007A}]+\\u{E007F}" +
    "|(?<=[\\p{Extended_Pictographic}\\p{Emoji_Modifier}\\uFE0F])\\u200D(?=\\p{Extended_Pictographic})" +
    "|(?<=[\\p{Extended_Pictographic}0-9#*])[\\uFE0E\\uFE0F]" +
    `|(?<=[${JOINER_SCRIPTS}])[\\u200C\\u200D](?=[${JOINER_SCRIPTS}])` +
    ")" +
    "|[\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180B-\\u180F\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\u3164\\uFE00-\\uFE0F\\uFEFF\\uFFA0\\uFFF9-\\uFFFB\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E007F}\\u{E0100}-\\u{E01EF}]",
  "gu"
);

export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE, (_match, keep: string | undefined) => keep ?? "");
}

const FLAG_SEQUENCE = new RegExp(
  "\\u{1F3F4}[\\u{E0030}-\\u{E0039}\\u{E0061}-\\u{E007A}]+\\u{E007F}",
  "gu"
);
const TAG_CHARACTER = new RegExp("[\\u{E0020}-\\u{E007E}]", "gu");

/** Decodes ASCII hidden in Unicode tag characters ("ASCII smuggling"), ignoring flags. */
export function tagSmuggledText(text: string): string {
  const matches = text.replace(FLAG_SEQUENCE, "").match(TAG_CHARACTER) ?? [];
  return matches
    .map((c) => String.fromCodePoint((c.codePointAt(0) ?? 0) - 0xe0000))
    .join("");
}

/** True if invisible Unicode in this text looks like a deliberate hidden payload. */
export function hasSmuggledText(text: string): boolean {
  // Tag characters have no legitimate use outside flag emoji, so any real run counts.
  return tagSmuggledText(text).length >= 4;
}

const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

/** Parsed like a browser would (which also defeats java\tscript: tricks). */
export function isSafeLink(href: string, allowed = SAFE_LINK_PROTOCOLS): boolean {
  try {
    return allowed.has(new URL(href, "https://relative.invalid/").protocol);
  } catch {
    return false;
  }
}

const SAFE_IMAGE_PROTOCOLS = new Set(["http:", "https:"]);

/** Renders an image: alt text only by default, since a client that auto-loads image URLs
 * would make a request to a page-chosen address (and whatever data is in that URL). */
export function renderImage(alt: string, src: string, images: ImageMode): string {
  const label = alt.replace(/\s+/g, " ").trim().slice(0, 200);
  if (images === "keep" && src !== "" && isSafeLink(src, SAFE_IMAGE_PROTOCOLS)) {
    return `![${label}](${src})`;
  }
  return label === "" ? "" : `[Image: ${label}]`;
}

const CODE_SPANS = /(^(?:```|~~~)[^\n]*\n[\s\S]*?^(?:```|~~~)[ \t]*$|`[^`\n]+`)/gm;
const HIDING_ATTRIBUTES =
  "(?:hidden|aria-hidden=[\"']?true[\"']?|style=[\"'][^\"']*(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|font-size\\s*:\\s*0|opacity\\s*:\\s*0)[^\"']*[\"'])";
const HIDDEN_HTML = new RegExp(
  `<([a-z][a-z0-9]*)\\b[^>]*\\s${HIDING_ATTRIBUTES}[^>]*>[\\s\\S]*?</\\1\\s*>`,
  "gi"
);

function sanitizeProse(
  prose: string,
  images: ImageMode,
  note: (hidden: string) => void
): string {
  const remove = (match: string): string => {
    note(match);
    return "";
  };
  return prose
    .replace(/<!--[\s\S]*?(?:-->|$)/g, remove)
    .replace(/^\[(?:\/\/|comment)\]:\s*(?:#|<>)[^\n]*$/gim, remove)
    .replace(/<(script|style|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, remove)
    .replace(HIDDEN_HTML, remove)
    .replace(/<img\b[^>]*>/gi, (tag) => {
      const attr = (name: string): string =>
        new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(tag)?.[1] ?? "";
      return renderImage(attr("alt"), attr("src"), images);
    })
    .replace(
      /!\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?[^)\n]*\)/g,
      (_m, alt: string, src: string) => renderImage(alt, src, images)
    )
    .replace(/!\[([^\]\n]*)\]\[[^\]\n]*\]/g, (_m, alt: string) =>
      renderImage(alt, "", "alt")
    )
    .replace(
      /\[([^\]\n]*)\]\(\s*<?([^)\s>]*)>?[^)\n]*\)/g,
      (link, text: string, href: string) => (isSafeLink(href) ? link : text)
    )
    .replace(/^\[[^\]\n]+\]:\s*<?(\S+?)>?(?:\s[^\n]*)?$/gm, (def, href: string) =>
      isSafeLink(href) ? def : ""
    );
}

/**
 * Cleans server-rendered markdown (which arrives without our HTML pipeline). Regex-based,
 * so best effort, and code is left untouched so samples stay intact.
 */
export function sanitizeMarkdown(
  markdown: string,
  images: ImageMode
): { text: string; suspicious: boolean } {
  let suspicious = false;
  const note = (hidden: string): void => {
    if (INJECTION_LIKE.test(hidden)) suspicious = true;
  };
  const parts = markdown.split(CODE_SPANS);
  const text = parts
    .map((part, i) => (i % 2 === 1 ? part : sanitizeProse(part, images, note)))
    .join("");
  return { text, suspicious };
}
