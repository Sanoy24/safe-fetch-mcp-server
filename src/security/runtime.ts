/**
 * Node's bundled Brotli decoder had an out-of-bounds write (CVE-2026-111497, fixed in the
 * releases below). This server decompresses whatever a site sends, so a hostile page can
 * reach that decoder directly. npm only warns about `engines`, so the check is made here too.
 */
const BROTLI_FIXED_IN: Readonly<Record<number, readonly [number, number]>> = {
  22: [23, 4],
  24: [22, 1],
  26: [12, 1]
};
const LAST_LINE_WITH_A_LISTED_FIX = 26;

/** False for a line that never got the fix, such as an end-of-life odd-numbered release. */
export function hasPatchedBrotli(version: string): boolean {
  const [major = 0, minor = 0, patch = 0] = version
    .replace(/^v/, "")
    .split(".")
    .map((part) => Number.parseInt(part, 10));
  if (major > LAST_LINE_WITH_A_LISTED_FIX) return true;
  const fix = BROTLI_FIXED_IN[major];
  if (!fix) return false;
  return minor > fix[0] || (minor === fix[0] && patch >= fix[1]);
}

/** Printed at startup on an affected runtime. Null when there's nothing to report. */
export function runtimeWarning(version: string = process.versions.node): string | null {
  if (hasPatchedBrotli(version)) return null;
  return (
    `WARNING: Node ${version} has a Brotli decoder vulnerability (CVE-2026-111497), so this ` +
    "server won't decode Brotli responses. Other sites still work. " +
    "Upgrade to Node 22.23.4, 24.22.1, 26.12.1 or later."
  );
}
