// Clean-install smoke test: packs the package exactly as npm would publish it,
// installs the tarball into an empty directory, and drives the installed binary
// over stdio with the MCP SDK client. Catches what unit tests can't: missing
// files in the tarball, a broken bin/shebang, or runtime-only dependency gaps.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
// Under `npm run`, npm_execpath points at npm's own CLI, so it can be run with node
// directly — no shell, on every OS. Outside npm, fall back to the npm on PATH.
const npmCli = process.env["npm_execpath"];
const run = (args, cwd) =>
  npmCli
    ? execFileSync(process.execPath, [npmCli, ...args], { cwd, encoding: "utf8" })
    : execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", args, {
        cwd,
        encoding: "utf8",
        shell: process.platform === "win32"
      });

function check(condition, message) {
  if (!condition) throw new Error(`smoke: ${message}`);
  console.error(`  ok  ${message}`);
}

const work = mkdtempSync(join(tmpdir(), "safe-fetch-smoke-"));
try {
  const [{ filename }] = JSON.parse(
    run(["pack", "--json", "--pack-destination", work], root)
  );
  writeFileSync(join(work, "package.json"), '{ "name": "smoke", "private": true }');
  run(["install", "--no-audit", "--no-fund", join(work, filename)], work);

  const installed = join(work, "node_modules", pkg.name);
  const binPath = join(installed, pkg.bin[pkg.name]);
  check(
    readFileSync(binPath, "utf8").startsWith("#!/usr/bin/env node"),
    "bin has a node shebang"
  );

  const sdk = (p) =>
    import(
      pathToFileURL(join(work, "node_modules/@modelcontextprotocol/sdk/dist/esm", p)).href
    );
  const { Client } = await sdk("client/index.js");
  const { StdioClientTransport } = await sdk("client/stdio.js");

  const client = new Client({ name: "smoke", version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [binPath],
      stderr: "ignore"
    })
  );
  try {
    check(
      client.getServerVersion()?.version === pkg.version,
      `server reports version ${pkg.version}`
    );

    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "fetch_url");
    check(tool !== undefined, "fetch_url is listed");
    check(tool?.outputSchema !== undefined, "fetch_url declares an outputSchema");

    const refused = await client.callTool({
      name: "fetch_url",
      arguments: { url: "http://169.254.169.254/latest/meta-data/" }
    });
    check(refused.isError === true, "cloud metadata is refused");
    check(
      refused.structuredContent?.error?.code === "POLICY_REJECTED",
      "refusal code is POLICY_REJECTED"
    );
  } finally {
    await client.close();
  }

  const bad = spawnSync(process.execPath, [binPath], {
    env: { ...process.env, SAFE_FETCH_TIMEOUT_MS: "abc" },
    encoding: "utf8",
    timeout: 10_000
  });
  check(bad.status === 1, "invalid config exits with status 1");
  check(
    /SAFE_FETCH_TIMEOUT_MS/.test(bad.stderr),
    "invalid config message names the variable"
  );

  console.error("smoke: passed");
} finally {
  rmSync(work, { recursive: true, force: true });
}
