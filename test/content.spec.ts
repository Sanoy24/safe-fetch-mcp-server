import { describe, it, expect } from "vitest";
import { toMarkdown, isTextualContentType } from "../src/content/toMarkdown.js";

describe("isTextualContentType", () => {
  it("treats text/*, JSON, and XML as textual", () => {
    expect(isTextualContentType("text/html")).toBe(true);
    expect(isTextualContentType("text/html; charset=utf-8")).toBe(true);
    expect(isTextualContentType("text/plain")).toBe(true);
    expect(isTextualContentType("application/json")).toBe(true);
    expect(isTextualContentType("application/xml")).toBe(true);
    expect(isTextualContentType("application/xhtml+xml")).toBe(true);
  });

  it("treats binary types as non-textual", () => {
    expect(isTextualContentType("image/png")).toBe(false);
    expect(isTextualContentType("application/octet-stream")).toBe(false);
    expect(isTextualContentType("application/pdf")).toBe(false);
  });
});

describe("toMarkdown", () => {
  it("converts HTML to clean markdown", () => {
    const html = "<h1>Hello</h1><p>World</p>";
    const markdown = toMarkdown(Buffer.from(html), "text/html");
    expect(markdown).toContain("# Hello");
    expect(markdown).toContain("World");
  });

  it("handles a content-type with a charset parameter", () => {
    const html = "<p>Hi</p>";
    const markdown = toMarkdown(Buffer.from(html), "text/html; charset=utf-8");
    expect(markdown).toContain("Hi");
  });

  it("strips script/style content instead of leaking it as text", () => {
    const html = "<html><head><style>body{color:red}</style></head><body><h1>Title</h1><script>evil()</script></body></html>";
    const markdown = toMarkdown(Buffer.from(html), "text/html");
    expect(markdown).toContain("Title");
    expect(markdown).not.toContain("color:red");
    expect(markdown).not.toContain("evil()");
  });

  it("passes through non-HTML textual content unchanged", () => {
    const text = '{"key":"value"}';
    const result = toMarkdown(Buffer.from(text), "application/json");
    expect(result).toBe(text);
  });
});
