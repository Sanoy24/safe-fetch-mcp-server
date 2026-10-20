import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import * as http from "node:http";
import { isIP, type AddressInfo } from "node:net";
import type { LookupAddress } from "node:dns";
import { safeFetch, GuardError } from "../src/security/index.js";
import type { Resolver } from "../src/security/resolveAndPin.js";
import type { SafeFetchConfig } from "../src/config.js";

// Public SSRF test vectors (docs/test-vectors.md). Each vector reproduces a bypass class
// that broke a real fetch server, and must be refused with POLICY_REJECTED. A generic
// "something threw" isn't enough: a DNS failure would pass for the wrong reason.
//
// Fully hermetic: a fake resolver answers every lookup (including wildcard-DNS names
// like *.nip.io), and redirect vectors use a local fixture. Nothing touches the network.

interface Vector {
  readonly id: string;
  readonly url: string;
  /** Public CVE or upstream issue this class comes from, if any. */
  readonly ref?: string;
}

/** Wildcard-DNS services embed the target IP in the hostname. */
const WILDCARD_DNS = /^(?<ip>\d{1,3}(?:\.\d{1,3}){3})\.(?:nip\.io|sslip\.io|xip\.io)$/;

const fakeResolver: Resolver = async (hostname): Promise<LookupAddress[]> => {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const family = isIP(host);
  if (family !== 0) return [{ address: host, family }];
  if (host === "localhost" || host === "localhost.") {
    return [
      { address: "127.0.0.1", family: 4 },
      { address: "::1", family: 6 }
    ];
  }
  const wildcard = WILDCARD_DNS.exec(host)?.groups?.["ip"];
  if (wildcard) return [{ address: wildcard, family: 4 }];
  if (host === "metadata.google.internal")
    return [{ address: "169.254.169.254", family: 4 }];
  throw Object.assign(new Error(`ENOTFOUND ${host}`), { code: "ENOTFOUND" });
};

const cfg: SafeFetchConfig = {
  allowLocal: false,
  allowlist: [],
  maxBytes: 1_000_000,
  timeoutMs: 2_000,
  maxRedirects: 5
};

export const DIRECT_VECTORS: readonly Vector[] = [
  // Cloud metadata
  {
    id: "V01",
    url: "http://169.254.169.254/latest/meta-data/",
    ref: "mcp-server-fetch #4143"
  },
  { id: "V02", url: "http://100.100.100.200/latest/meta-data/" },
  { id: "V03", url: "http://[fd00:ec2::254]/latest/meta-data/" },
  { id: "V04", url: "http://metadata.google.internal/computeMetadata/v1/" },
  // IPv6 forms that embed or alias an internal IPv4
  { id: "V05", url: "http://[::ffff:127.0.0.1]/", ref: "CVE-2026-49857" },
  { id: "V06", url: "http://[::ffff:7f00:1]/" },
  { id: "V07", url: "http://[0:0:0:0:0:ffff:169.254.169.254]/" },
  { id: "V08", url: "http://[::127.0.0.1]/" },
  { id: "V09", url: "http://[64:ff9b::a9fe:a9fe]/" },
  { id: "V10", url: "http://[2002:a9fe:a9fe::]/" },
  // Bracketed IPv6 literals
  { id: "V11", url: "http://[::1]/", ref: "CVE-2026-80347" },
  { id: "V12", url: "http://[::]/" },
  { id: "V13", url: "http://[fe80::1]/" },
  { id: "V14", url: "http://[fc00::1]/" },
  // Alternate IPv4 encodings
  { id: "V15", url: "http://2130706433/" },
  { id: "V16", url: "http://0x7f000001/" },
  { id: "V17", url: "http://0177.0.0.1/" },
  { id: "V18", url: "http://017700000001/" },
  { id: "V19", url: "http://0x7f.1/" },
  { id: "V20", url: "http://127.1/" },
  { id: "V21", url: "http://0/" },
  { id: "V22", url: "http://%31%32%37.0.0.1/" },
  { id: "V23", url: "http://①②⑦.⓪.⓪.①/" },
  { id: "V24", url: "http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/" },
  // Hostnames that resolve internally
  { id: "V25", url: "http://localhost/" },
  { id: "V26", url: "http://localhost./" },
  { id: "V27", url: "http://ＬＯＣＡＬＨＯＳＴ/" },
  { id: "V28", url: "http://127.0.0.1.nip.io/" },
  { id: "V29", url: "http://169.254.169.254.sslip.io/" },
  { id: "V30", url: "http://10.0.0.5.nip.io/" },
  // Private and special-purpose ranges
  { id: "V31", url: "http://10.0.0.1/" },
  { id: "V32", url: "http://172.16.0.1/" },
  { id: "V33", url: "http://192.168.0.1/" },
  { id: "V34", url: "http://100.64.0.1/" },
  { id: "V35", url: "http://224.0.0.1/" },
  { id: "V36", url: "http://255.255.255.255/" },
  // Parser confusion: userinfo and backslash tricks
  { id: "V37", url: "http://example.com@127.0.0.1/" },
  { id: "V38", url: "http://127.0.0.1\\@example.com/" },
  { id: "V39", url: "http://user:pass@example.com/" },
  // Schemes that must never be fetched
  { id: "V40", url: "file:///etc/passwd", ref: "mcp-server-fetch #4205" },
  { id: "V41", url: "gopher://127.0.0.1:6379/_INFO" },
  { id: "V42", url: "dict://127.0.0.1:11211/stats" },
  { id: "V43", url: "ftp://example.com/" },
  { id: "V44", url: "data:text/plain,hello" },
  { id: "V45", url: "javascript:alert(1)" }
];

describe("public SSRF test vectors: direct requests", () => {
  it.each(DIRECT_VECTORS.map((v) => [v.id, v.url] as const))(
    "%s refuses %s with POLICY_REJECTED",
    async (_id, url) => {
      const err = await safeFetch(url, cfg, { resolve: fakeResolver }).then(
        () => undefined,
        (e: unknown) => e
      );
      expect(err, `${url} was fetched`).toBeInstanceOf(GuardError);
      expect((err as GuardError).code).toBe("POLICY_REJECTED");
    }
  );
});

// Metadata must stay refused even when the operator opts into local access. Without
// this pass, a metadata address that also sits in a private range (100.100.100.200 is
// inside CGNAT) would be "covered" only by the default private-range block.
export const ALWAYS_FORBIDDEN_IDS: readonly string[] = [
  "V01",
  "V02",
  "V03",
  "V04",
  "V07",
  "V09",
  "V10",
  "V13",
  "V24",
  "V29",
  "V35",
  "V36"
];

describe("public SSRF test vectors: never allowed, even with SAFE_FETCH_ALLOW_LOCAL", () => {
  const vectors = DIRECT_VECTORS.filter((v) => ALWAYS_FORBIDDEN_IDS.includes(v.id));

  it.each(vectors.map((v) => [v.id, v.url] as const))(
    "%s refuses %s with allowLocal on",
    async (_id, url) => {
      const err = await safeFetch(
        url,
        { ...cfg, allowLocal: true },
        { resolve: fakeResolver }
      ).then(
        () => undefined,
        (e: unknown) => e
      );
      expect(err, `${url} was fetched with allowLocal on`).toBeInstanceOf(GuardError);
      expect((err as GuardError).code).toBe("POLICY_REJECTED");
    }
  );
});

// Redirect vectors: a public-looking entry point (here a trusted local fixture) that
// redirects somewhere forbidden. Every hop must be re-checked.
export const REDIRECT_VECTORS: readonly Vector[] = [
  {
    id: "R01",
    url: "http://169.254.169.254/latest/meta-data/",
    ref: "mcp-server-fetch #4116"
  },
  { id: "R02", url: "//169.254.169.254/latest/meta-data/" },
  { id: "R03", url: "http://[::ffff:169.254.169.254]/" },
  { id: "R04", url: "http://100.100.100.200/" },
  { id: "R05", url: "file:///etc/passwd" },
  { id: "R06", url: "http://169.254.169.254.nip.io/" }
];

describe("public SSRF test vectors: redirect targets", () => {
  let server: http.Server;
  let base: string;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const target = decodeURIComponent((req.url ?? "/").slice("/to/".length));
      res.writeHead(Number(req.headers["x-status"] ?? 302), { location: target });
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it.each(REDIRECT_VECTORS.map((v) => [v.id, v.url] as const))(
    "%s refuses a redirect to %s",
    async (_id, target) => {
      // The fixture itself is an opted-in local target; the redirect target is not.
      const err = await safeFetch(
        `${base}/to/${encodeURIComponent(target)}`,
        { ...cfg, allowLocal: true },
        { resolve: fakeResolver }
      ).then(
        () => undefined,
        (e: unknown) => e
      );
      expect(err, `redirect to ${target} was followed`).toBeInstanceOf(GuardError);
      expect((err as GuardError).code).toBe("POLICY_REJECTED");
    }
  );
});

describe("docs/test-vectors.md", () => {
  it("lists every vector, so the published list can't drift from the tests", () => {
    const doc = readFileSync(new URL("../docs/test-vectors.md", import.meta.url), "utf8");
    for (const v of [...DIRECT_VECTORS, ...REDIRECT_VECTORS]) {
      expect(doc, `${v.id} missing from docs/test-vectors.md`).toContain(`| ${v.id} `);
    }
  });
});
