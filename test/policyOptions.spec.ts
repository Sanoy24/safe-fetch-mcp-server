import { describe, it, expect } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, UrlPolicyError } from "../src/security/index.js";
import { parseAndValidateUrl } from "../src/security/urlPolicy.js";
import { assertRedirectAllowed } from "../src/security/redirects.js";
import { loadConfig, ConfigError, type SafeFetchConfig } from "../src/config.js";

// Optional, operator-controlled egress tightening (threat-model rows 18-20).

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: true,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    ...overrides
  };
}

describe("SAFE_FETCH_HTTPS_ONLY", () => {
  it("refuses plain http:// when enabled", () => {
    expect(() =>
      parseAndValidateUrl("http://example.com/", testConfig({ httpsOnly: true }))
    ).toThrow(/https/i);
  });

  it("still allows https:// when enabled", () => {
    expect(
      parseAndValidateUrl("https://example.com/", testConfig({ httpsOnly: true })).href
    ).toBe("https://example.com/");
  });

  it("allows http:// by default", () => {
    expect(() => parseAndValidateUrl("http://example.com/", testConfig())).not.toThrow();
  });
});

describe("SAFE_FETCH_ALLOWED_PORTS", () => {
  const cfg = testConfig({ allowedPorts: [443, 8443] });

  it("allows listed ports, including the scheme default", () => {
    expect(() => parseAndValidateUrl("https://example.com/", cfg)).not.toThrow();
    expect(() => parseAndValidateUrl("https://example.com:8443/", cfg)).not.toThrow();
  });

  it("refuses unlisted ports, including an implicit :80", () => {
    expect(() => parseAndValidateUrl("https://example.com:22/", cfg)).toThrow(
      UrlPolicyError
    );
    expect(() => parseAndValidateUrl("http://example.com/", cfg)).toThrow(/port 80/);
  });

  it("allows any port when unset", () => {
    expect(() =>
      parseAndValidateUrl("http://example.com:6379/", testConfig())
    ).not.toThrow();
  });

  it("is enforced on redirect hops too", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(302, { location: "http://127.0.0.1:1/" });
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      await expect(
        safeFetch(`http://127.0.0.1:${port}/`, testConfig({ allowedPorts: [port] }))
      ).rejects.toThrow(/port 1 /);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("HTTPS → HTTP redirect downgrade", () => {
  const https = new URL("https://example.com/a");
  const http_ = new URL("http://example.com/b");

  it("is refused by default", () => {
    expect(() => assertRedirectAllowed(https, http_, testConfig())).toThrow(
      UrlPolicyError
    );
  });

  it("can be allowed explicitly", () => {
    expect(() =>
      assertRedirectAllowed(https, http_, testConfig({ allowHttpsDowngrade: true }))
    ).not.toThrow();
  });

  it("does not affect http → https or same-scheme redirects", () => {
    expect(() => assertRedirectAllowed(http_, https, testConfig())).not.toThrow();
    expect(() => assertRedirectAllowed(https, https, testConfig())).not.toThrow();
  });
});

describe("config parsing for the new options", () => {
  it("parses ports and booleans", () => {
    const cfg = loadConfig({
      SAFE_FETCH_HTTPS_ONLY: "true",
      SAFE_FETCH_ALLOWED_PORTS: "443, 8443",
      SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE: "1"
    });
    expect(cfg.httpsOnly).toBe(true);
    expect(cfg.allowedPorts).toEqual([443, 8443]);
    expect(cfg.allowHttpsDowngrade).toBe(true);
  });

  it("rejects an invalid port list", () => {
    expect(() => loadConfig({ SAFE_FETCH_ALLOWED_PORTS: "443,http" })).toThrow(
      ConfigError
    );
    expect(() => loadConfig({ SAFE_FETCH_ALLOWED_PORTS: "70000" })).toThrow(ConfigError);
  });
});
