import { describe, it, expect } from "vitest";
import {
  ConfigError,
  isLoopbackHost,
  loadConfig,
  loadHttpConfig
} from "../src/config.js";

describe("loadHttpConfig", () => {
  it("defaults to host 127.0.0.1 and port 3000", () => {
    const cfg = loadHttpConfig({});
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.port).toBe(3000);
  });

  it("accepts a valid PORT", () => {
    const cfg = loadHttpConfig({ PORT: "8080" });
    expect(cfg.port).toBe(8080);
  });

  it("rejects an out-of-range PORT instead of silently using the default", () => {
    expect(() => loadHttpConfig({ PORT: "99999" })).toThrow(ConfigError);
    expect(() => loadHttpConfig({ PORT: "0" })).toThrow(ConfigError);
  });

  it("rejects a non-numeric PORT and names the variable", () => {
    expect(() => loadHttpConfig({ PORT: "not-a-port" })).toThrow(/PORT/);
    expect(() => loadHttpConfig({ PORT: "80abc" })).toThrow(ConfigError);
  });

  it("parses SAFE_FETCH_ALLOWED_ORIGINS into a lowercase list", () => {
    const cfg = loadHttpConfig({
      SAFE_FETCH_ALLOWED_ORIGINS: "https://A.example, https://B.example"
    });
    expect(cfg.allowedOrigins).toEqual(["https://a.example", "https://b.example"]);
  });
});

describe("loadConfig", () => {
  it("uses safe defaults when nothing is set", () => {
    expect(loadConfig({})).toEqual({
      allowLocal: false,
      allowlist: [],
      maxBytes: 5_000_000,
      timeoutMs: 10_000,
      maxRedirects: 5,
      httpsOnly: false,
      allowHttpsDowngrade: false,
      allowedPorts: [],
      cache: { ttlMs: 0, maxEntries: 100, maxBytes: 20_000_000 },
      logFormat: "text"
    });
  });

  it("accepts true/false and 1/0 for SAFE_FETCH_ALLOW_LOCAL", () => {
    expect(loadConfig({ SAFE_FETCH_ALLOW_LOCAL: "TRUE" }).allowLocal).toBe(true);
    expect(loadConfig({ SAFE_FETCH_ALLOW_LOCAL: "1" }).allowLocal).toBe(true);
    expect(loadConfig({ SAFE_FETCH_ALLOW_LOCAL: "false" }).allowLocal).toBe(false);
    expect(loadConfig({ SAFE_FETCH_ALLOW_LOCAL: "0" }).allowLocal).toBe(false);
  });

  it("rejects an ambiguous SAFE_FETCH_ALLOW_LOCAL rather than guessing", () => {
    expect(() => loadConfig({ SAFE_FETCH_ALLOW_LOCAL: "yes" })).toThrow(
      /SAFE_FETCH_ALLOW_LOCAL/
    );
  });

  it("rejects invalid limits instead of silently using the default", () => {
    expect(() => loadConfig({ SAFE_FETCH_TIMEOUT_MS: "abc" })).toThrow(ConfigError);
    expect(() => loadConfig({ SAFE_FETCH_TIMEOUT_MS: "-5" })).toThrow(ConfigError);
    expect(() => loadConfig({ SAFE_FETCH_MAX_BYTES: "1.5" })).toThrow(ConfigError);
    expect(() => loadConfig({ SAFE_FETCH_MAX_REDIRECTS: "100" })).toThrow(ConfigError);
  });

  it("allows SAFE_FETCH_MAX_REDIRECTS=0 to disable redirects", () => {
    expect(loadConfig({ SAFE_FETCH_MAX_REDIRECTS: "0" }).maxRedirects).toBe(0);
  });

  it("treats an empty value as unset", () => {
    expect(loadConfig({ SAFE_FETCH_TIMEOUT_MS: "" }).timeoutMs).toBe(10_000);
  });
});

describe("isLoopbackHost", () => {
  it("recognizes loopback bind addresses", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("0.0.0.0")).toBe(false);
    expect(isLoopbackHost("192.168.1.10")).toBe(false);
  });
});
