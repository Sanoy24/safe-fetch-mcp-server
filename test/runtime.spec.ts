import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import * as http from "node:http";
import { join } from "node:path";
import * as zlib from "node:zlib";
import type { AddressInfo } from "node:net";
import { GuardError, safeFetch } from "../src/security/index.js";
import { hasPatchedBrotli, runtimeWarning } from "../src/security/runtime.js";
import type { SafeFetchConfig } from "../src/config.js";

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

describe("hasPatchedBrotli", () => {
  it.each([
    ["22.23.4", true],
    ["22.23.5", true],
    ["22.24.0", true],
    ["24.22.1", true],
    ["24.22.2", true],
    ["24.23.0", true],
    ["26.12.1", true],
    ["26.13.0", true],
    ["27.0.0", true],
    ["v24.22.1", true],
    ["22.23.3", false],
    ["22.22.9", false],
    ["22.0.0", false],
    ["24.22.0", false],
    ["24.4.1", false],
    ["26.12.0", false],
    ["23.11.0", false], // end of life, never fixed
    ["25.9.0", false], // end of life, never fixed
    ["20.19.0", false],
    ["not a version", false]
  ])("%s → %s", (version, expected) => {
    expect(hasPatchedBrotli(version)).toBe(expected);
  });
});

describe("runtimeWarning", () => {
  it("names the CVE and the fix on an affected runtime", () => {
    const warning = runtimeWarning("24.4.1");
    expect(warning).toContain("CVE-2026-111497");
    expect(warning).toContain("24.22.1");
  });

  it("says nothing on a patched runtime", () => {
    expect(runtimeWarning("24.22.1")).toBeNull();
  });

  it("is printed by the real server exactly when this runtime is affected", async () => {
    const server = join(import.meta.dirname, "..", "dist", "index.js");
    const child = spawn(process.execPath, [server], {
      stdio: ["pipe", "ignore", "pipe"]
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    await new Promise<void>((resolve) => {
      child.stderr.on("data", () => {
        if (stderr.includes("running on stdio")) resolve();
      });
    });
    child.kill();
    expect(stderr.includes("CVE-2026-111497")).toBe(
      !hasPatchedBrotli(process.versions.node)
    );
  });
});

describe("a runtime with the Brotli decoder bug", () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  /** A hostile site: it sends this encoding whatever the client asked for. */
  async function serve(
    encoding: string,
    body: Buffer
  ): Promise<{ url: string; accepted: () => string | undefined }> {
    let accepted: string | undefined;
    server = http.createServer((req, res) => {
      accepted = req.headers["accept-encoding"] as string | undefined;
      res.writeHead(200, { "content-type": "text/plain", "content-encoding": encoding });
      res.end(body);
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return {
      url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`,
      accepted: () => accepted
    };
  }

  it("doesn't offer Brotli", async () => {
    const site = await serve("gzip", zlib.gzipSync("hello"));
    await safeFetch(site.url, testConfig({ brotli: false }));
    expect(site.accepted()).toBe("gzip, deflate");
  });

  it("refuses a Brotli response the site sent anyway, without decoding it", async () => {
    const site = await serve("br", zlib.brotliCompressSync("hello"));
    const err = await safeFetch(site.url, testConfig({ brotli: false })).then(
      () => undefined,
      (e: unknown) => e
    );
    expect(err).toBeInstanceOf(GuardError);
    expect((err as GuardError).code).toBe("INVALID_RESPONSE");
    expect((err as GuardError).message).not.toContain("hello");
  });

  it("still decodes gzip", async () => {
    const site = await serve("gzip", zlib.gzipSync("hello"));
    const result = await safeFetch(site.url, testConfig({ brotli: false }));
    expect(result.body.toString()).toBe("hello");
  });
});

describe("a patched runtime", () => {
  it("is what the setting defaults to following", async () => {
    let accepted: string | undefined;
    const server = http.createServer((req, res) => {
      accepted = req.headers["accept-encoding"] as string | undefined;
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("hi");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    await safeFetch(url, testConfig());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    expect(accepted).toBe(
      hasPatchedBrotli(process.versions.node) ? "gzip, br, deflate" : "gzip, deflate"
    );
  });
});
