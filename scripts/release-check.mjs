// Verifies that every place a version or registry name appears agrees, so a release
// can't ship with a stale server.json (the MCP Registry rejects mismatches).
//
//   node scripts/release-check.mjs              check consistency
//   node scripts/release-check.mjs --tag v1.2.3 also require the git tag to match
//   node scripts/release-check.mjs --notes      print this version's CHANGELOG section
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const read = (file) => readFileSync(join(root, file), "utf8");
const pkg = JSON.parse(read("package.json"));
const server = JSON.parse(read("server.json"));
const { version } = pkg;

/** The body of `## [version] ...` up to the next `## [` heading or link block. */
function changelogSection(changelog, wanted) {
  const lines = changelog.split("\n");
  const start = lines.findIndex((line) => line.startsWith(`## [${wanted}]`));
  if (start === -1) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex(
    (line) => line.startsWith("## [") || /^\[[^\]]+\]: /.test(line)
  );
  return (end === -1 ? rest : rest.slice(0, end)).join("\n").trim();
}

const section = changelogSection(read("CHANGELOG.md"), version);
const args = process.argv.slice(2);

if (args.includes("--notes")) {
  if (section === null) throw new Error(`CHANGELOG.md has no "## [${version}]" section.`);
  process.stdout.write(section + "\n");
  process.exit(0);
}

const problems = [];
const expect = (ok, message) => {
  if (!ok) problems.push(message);
};

expect(
  server.version === version,
  `server.json version ${server.version} != package.json ${version}`
);
for (const p of server.packages ?? []) {
  expect(p.version === version, `server.json package version ${p.version} != ${version}`);
  expect(p.identifier === pkg.name, `server.json package ${p.identifier} != ${pkg.name}`);
}
expect(
  server.name === pkg.mcpName,
  `server.json name ${server.name} != package.json mcpName ${pkg.mcpName}`
);
expect(section !== null, `CHANGELOG.md has no "## [${version}]" section`);

const tagIndex = args.indexOf("--tag");
if (tagIndex !== -1) {
  const tag = args[tagIndex + 1];
  expect(tag === `v${version}`, `tag ${tag} != v${version}`);
}

if (problems.length > 0) {
  console.error("release-check failed:\n  - " + problems.join("\n  - "));
  process.exit(1);
}
console.error(`release-check: ${pkg.name}@${version} is consistent`);
