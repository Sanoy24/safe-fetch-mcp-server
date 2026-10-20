import { describe, it, expect } from "vitest";
import { hostMatches, parseHostPatterns } from "../src/security/hostPatterns.js";
import { parseAndValidateUrl, UrlPolicyError } from "../src/security/urlPolicy.js";
import { loadConfig, ConfigError, type SafeFetchConfig } from "../src/config.js";

// SAFE_FETCH_ALLOWLIST / SAFE_FETCH_DENYLIST host patterns: exact hosts and "*." suffix
// wildcards, normalized the same way the WHATWG URL parser normalizes hostnames.

function policy(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: false,
    allowlist: [],
    maxBytes: 1_000,
    timeoutMs: 1_000,
    maxRedirects: 5,
    ...overrides
  };
}

describe("hostMatches", () => {
  it("matches an exact host case-insensitively, ignoring a trailing dot", () => {
    expect(hostMatches("docs.python.org", ["docs.python.org"])).toBe(true);
    expect(hostMatches("DOCS.python.org", ["docs.python.org"])).toBe(true);
    expect(hostMatches("docs.python.org.", ["docs.python.org"])).toBe(true);
    expect(hostMatches("python.org", ["docs.python.org"])).toBe(false);
  });

  it("matches *.example.com for subdomains at any depth, but not the apex", () => {
    const patterns = ["*.example.com"];
    expect(hostMatches("a.example.com", patterns)).toBe(true);
    expect(hostMatches("a.b.example.com", patterns)).toBe(true);
    expect(hostMatches("example.com", patterns)).toBe(false);
  });

  it("is not fooled by look-alike suffixes", () => {
    expect(hostMatches("evilexample.com", ["*.example.com"])).toBe(false);
    expect(hostMatches("example.com.evil.net", ["*.example.com"])).toBe(false);
    expect(hostMatches("notexample.com", ["example.com"])).toBe(false);
  });
});

describe("parseHostPatterns", () => {
  it("normalizes case, trailing dots and Unicode (to punycode)", () => {
    expect(parseHostPatterns("X", " Docs.Python.org., *.Bücher.example ")).toEqual([
      "docs.python.org",
      "*.xn--bcher-kva.example"
    ]);
  });

  it("rejects entries that aren't a host or *.host", () => {
    for (const bad of [
      "*",
      "*.",
      "http://example.com",
      "example.com/path",
      "a*.b.com",
      "*.*.com",
      "exa mple.com"
    ]) {
      expect(() => parseHostPatterns("SAFE_FETCH_ALLOWLIST", bad), bad).toThrow(
        ConfigError
      );
    }
  });

  it("accepts IPv4 and bracketed IPv6 literals as exact entries", () => {
    expect(parseHostPatterns("X", "93.184.216.34, [2606:4700::1111]")).toEqual([
      "93.184.216.34",
      "[2606:4700::1111]"
    ]);
    expect(() => parseHostPatterns("X", "example.com:8080")).toThrow(ConfigError);
  });

  it("names the variable in the error", () => {
    expect(() => parseHostPatterns("SAFE_FETCH_DENYLIST", "*")).toThrow(
      /SAFE_FETCH_DENYLIST/
    );
  });
});

describe("URL policy with allow/deny lists", () => {
  it("allows wildcard subdomains from SAFE_FETCH_ALLOWLIST", () => {
    const cfg = policy({ allowlist: ["*.python.org"] });
    expect(() => parseAndValidateUrl("https://docs.python.org/3/", cfg)).not.toThrow();
    expect(() => parseAndValidateUrl("https://example.com/", cfg)).toThrow(
      UrlPolicyError
    );
  });

  it("refuses hosts on SAFE_FETCH_DENYLIST", () => {
    const cfg = policy({ denylist: ["*.internal.corp", "tracker.example"] });
    expect(() => parseAndValidateUrl("https://wiki.internal.corp/", cfg)).toThrow(
      /DENYLIST/
    );
    expect(() => parseAndValidateUrl("https://tracker.example/", cfg)).toThrow(
      UrlPolicyError
    );
    expect(() => parseAndValidateUrl("https://example.com/", cfg)).not.toThrow();
  });

  it("lets the denylist win over the allowlist", () => {
    const cfg = policy({ allowlist: ["*.example.com"], denylist: ["admin.example.com"] });
    expect(() => parseAndValidateUrl("https://www.example.com/", cfg)).not.toThrow();
    expect(() => parseAndValidateUrl("https://admin.example.com/", cfg)).toThrow(
      /DENYLIST/
    );
  });

  it("matches Unicode hostnames in URLs against punycode patterns", () => {
    const cfg = policy({ allowlist: parseHostPatterns("X", "bücher.example") });
    expect(() => parseAndValidateUrl("https://bücher.example/", cfg)).not.toThrow();
  });

  it("loads both lists from the environment", () => {
    const cfg = loadConfig({
      SAFE_FETCH_ALLOWLIST: "*.python.org",
      SAFE_FETCH_DENYLIST: "evil.python.org"
    });
    expect(cfg.allowlist).toEqual(["*.python.org"]);
    expect(cfg.denylist).toEqual(["evil.python.org"]);
  });
});
