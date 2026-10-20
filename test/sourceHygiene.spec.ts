import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// "Trojan Source" guard (CVE-2021-42574): invisible and bidi-control characters can make
// code read differently to a reviewer than it runs. Source must spell them as \uXXXX
// escapes. This also catches tooling that silently turns escapes into the real characters.
const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/;

describe("source hygiene", () => {
  it("has no literal invisible or bidi-control characters in tracked code", () => {
    const files = execFileSync("git", ["ls-files", "src", "test", "scripts", "skills"], {
      encoding: "utf8"
    })
      .split("\n")
      .filter((f) => /\.(ts|mjs|js|json|md)$/.test(f));

    const offenders = files.filter((f) => INVISIBLE.test(readFileSync(f, "utf8")));

    expect(files.length).toBeGreaterThan(10);
    expect(offenders).toEqual([]);
  });
});
