import { describe, it, expect } from "vitest";
import { loadHttpConfig } from "../src/config.js";

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

  it("falls back to the default for an out-of-range PORT", () => {
    const cfg = loadHttpConfig({ PORT: "99999" });
    expect(cfg.port).toBe(3000);
  });

  it("falls back to the default for a non-numeric PORT", () => {
    const cfg = loadHttpConfig({ PORT: "not-a-port" });
    expect(cfg.port).toBe(3000);
  });

  it("parses SAFE_FETCH_ALLOWED_ORIGINS into a lowercase list", () => {
    const cfg = loadHttpConfig({
      SAFE_FETCH_ALLOWED_ORIGINS: "https://A.example, https://B.example"
    });
    expect(cfg.allowedOrigins).toEqual(["https://a.example", "https://b.example"]);
  });
});
