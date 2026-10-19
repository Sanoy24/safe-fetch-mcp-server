import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, ResolutionError } from "../src/security/index.js";
import type { Resolver } from "../src/security/resolveAndPin.js";
import type { SafeFetchConfig } from "../src/config.js";

// Rows 7 (DNS rebinding) and the "validate EVERY resolved address" rule, proven with
// a fake resolver instead of real DNS.

function testConfig(overrides: Partial<SafeFetchConfig> = {}): SafeFetchConfig {
  return {
    allowLocal: false,
    allowlist: [],
    maxBytes: 5_000_000,
    timeoutMs: 2_000,
    maxRedirects: 5,
    ...overrides
  };
}

describe("DNS resolution and connection pinning", () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  it("connects to the validated address and never re-resolves (DNS rebinding)", async () => {
    let peerAddress: string | undefined;
    server = http.createServer((req, res) => {
      peerAddress = req.socket.localAddress;
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`host=${req.headers.host}`);
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    // First answer is the (opted-in) local fixture; any later lookup "rebinds" to
    // cloud metadata. If the HTTP client resolved again, it would get the metadata
    // address (via this resolver) or ENOTFOUND (via real DNS) — not the fixture.
    let calls = 0;
    const rebindingResolver: Resolver = async () => {
      calls += 1;
      return calls === 1
        ? [{ address: "127.0.0.1", family: 4 }]
        : [{ address: "169.254.169.254", family: 4 }];
    };

    const result = await safeFetch(
      `http://rebind.test:${port}/`,
      testConfig({ allowLocal: true }),
      { resolve: rebindingResolver }
    );

    expect(calls).toBe(1);
    expect(peerAddress).toBe("127.0.0.1");
    expect(result.status).toBe(200);
    // Host header carries the original hostname and the non-default port.
    expect(result.body.toString("utf-8")).toBe(`host=rebind.test:${port}`);
  });

  it("refuses a host whose answers mix public and private addresses", async () => {
    const mixedResolver: Resolver = async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 }
    ];

    await expect(
      safeFetch("http://mixed.test/", testConfig(), { resolve: mixedResolver })
    ).rejects.toThrow(ResolutionError);
  });

  it("refuses a host with a metadata answer even when ALLOW_LOCAL is on", async () => {
    const resolver: Resolver = async () => [
      { address: "127.0.0.1", family: 4 },
      { address: "fd00:ec2::254", family: 6 }
    ];

    await expect(
      safeFetch("http://imds.test/", testConfig({ allowLocal: true }), {
        resolve: resolver
      })
    ).rejects.toThrow(ResolutionError);
  });

  it("refuses a host that resolves to no addresses", async () => {
    const emptyResolver: Resolver = async () => [];

    await expect(
      safeFetch("http://empty.test/", testConfig(), { resolve: emptyResolver })
    ).rejects.toThrow(ResolutionError);
  });
});
