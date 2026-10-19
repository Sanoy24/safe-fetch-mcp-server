import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { FETCH_ERROR_CODES } from "../src/security/errors.js";
import { DEFAULT_MAX_CHARS, FetchUrlInput } from "../src/tools/fetchUrl.js";

// The companion skill (skills/safe-web-fetch) is shipped separately from the
// server, so guard it against drifting from the real tool contract.
const skill = readFileSync(
  new URL("../skills/safe-web-fetch/SKILL.md", import.meta.url),
  "utf8"
);

describe("safe-web-fetch companion skill", () => {
  it("has the frontmatter marketplaces require", () => {
    expect(skill).toMatch(/^---\nname: safe-web-fetch\ndescription: .+\n/);
  });

  it("documents every error code the tool can return", () => {
    for (const code of FETCH_ERROR_CODES) {
      expect(skill, `missing ${code}`).toContain(`\`${code}\``);
    }
  });

  it("documents every tool argument", () => {
    for (const arg of Object.keys(FetchUrlInput.shape)) {
      expect(skill, `missing ${arg}`).toContain(`\`${arg}\``);
    }
  });

  it("states the real default for max_chars", () => {
    expect(skill).toContain(`default ${DEFAULT_MAX_CHARS}`);
  });
});
