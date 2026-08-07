import { isIPv4, isIPv6 } from "node:net";

/**
 * No third-party IP-classification library is used here (ADR-004: the `ip` npm
 * package shipped an SSRF-bypass CVE). CIDR ranges and IPv6 parsing are implemented
 * directly against explicit ranges and covered by regression tests.
 */

interface Cidr4 {
  readonly base: number;
  readonly prefix: number;
}

interface Cidr6 {
  readonly base: bigint;
  readonly prefix: number;
}

const FULL_V6_MASK = (1n << 128n) - 1n;

function ipv4ToInt(ip: string): number {
  const octets = ip.split(".").map((part) => Number.parseInt(part, 10));
  const [a, b, c, d] = octets;
  return (((a ?? 0) << 24) | ((b ?? 0) << 16) | ((c ?? 0) << 8) | (d ?? 0)) >>> 0;
}

function parseCidr4(cidr: string): Cidr4 {
  const [addr, prefixStr] = cidr.split("/");
  if (!addr || !prefixStr) throw new Error(`Invalid IPv4 CIDR: ${cidr}`);
  return { base: ipv4ToInt(addr), prefix: Number.parseInt(prefixStr, 10) };
}

function isInCidr4(ip: number, cidr: Cidr4): boolean {
  if (cidr.prefix === 0) return true;
  const mask = cidr.prefix === 32 ? 0xffffffff : (0xffffffff << (32 - cidr.prefix)) >>> 0;
  return (ip & mask) >>> 0 === (cidr.base & mask) >>> 0;
}

/**
 * Expands any valid textual IPv6 address (including "::" compression and an
 * embedded trailing IPv4 literal, e.g. "::ffff:127.0.0.1") into 8 16-bit groups.
 * Returns null for anything that doesn't parse — callers must fail closed on null.
 */
function expandIPv6Groups(rawAddress: string): number[] | null {
  let address = rawAddress;
  const zoneIndex = address.indexOf("%");
  if (zoneIndex !== -1) address = address.slice(0, zoneIndex);

  const doubleColonParts = address.split("::");
  if (doubleColonParts.length > 2) return null;
  const hasCompression = doubleColonParts.length === 2;

  const headRaw = doubleColonParts[0] ?? "";
  const tailRaw = hasCompression ? (doubleColonParts[1] ?? "") : "";

  const expandSide = (raw: string): string[] | null => {
    if (raw === "") return [];
    const parts = raw.split(":");
    const last = parts[parts.length - 1];
    if (last !== undefined && last.includes(".")) {
      if (!isIPv4(last)) return null;
      const asInt = ipv4ToInt(last);
      const high = ((asInt >>> 16) & 0xffff).toString(16);
      const low = (asInt & 0xffff).toString(16);
      parts.splice(parts.length - 1, 1, high, low);
    }
    for (const part of parts) {
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
    }
    return parts;
  };

  const head = expandSide(headRaw);
  const tail = !hasCompression ? [] : expandSide(tailRaw);
  if (head === null || tail === null) return null;

  const total = head.length + tail.length;
  const missing = 8 - total;
  if (hasCompression) {
    if (missing < 0) return null;
  } else if (missing !== 0) {
    return null;
  }

  const groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  return groups.map((g) => Number.parseInt(g, 16));
}

function groupsToBigInt(groups: number[]): bigint {
  let result = 0n;
  for (const group of groups) {
    result = (result << 16n) | BigInt(group);
  }
  return result;
}

function parseCidr6(cidr: string): Cidr6 {
  const [addr, prefixStr] = cidr.split("/");
  if (!addr || !prefixStr) throw new Error(`Invalid IPv6 CIDR: ${cidr}`);
  const groups = expandIPv6Groups(addr);
  if (!groups) throw new Error(`Invalid IPv6 CIDR base: ${cidr}`);
  return { base: groupsToBigInt(groups), prefix: Number.parseInt(prefixStr, 10) };
}

function isInCidr6(ip: bigint, cidr: Cidr6): boolean {
  if (cidr.prefix === 0) return true;
  const hostBits = BigInt(128 - cidr.prefix);
  const mask = FULL_V6_MASK ^ ((1n << hostBits) - 1n);
  return (ip & mask) === (cidr.base & mask);
}

// Row references are to the threat matrix in .claude/skills/secure-fetch-ssrf/SKILL.md
//
// Split into two tiers, deliberately:
//   - LOCAL_*: loopback, RFC-1918, ULA — legitimate to opt into via
//     SAFE_FETCH_ALLOW_LOCAL for a trusted local-dev target.
//   - ALWAYS_BLOCKED_*: link-local / cloud metadata (169.254.0.0/16, fe80::/10) —
//     the single most dangerous SSRF outcome (cloud credential theft) and never
//     something "local dev access" should imply. Never bypassed by ALLOW_LOCAL.
const LOCAL_IPV4_CIDRS: Cidr4[] = [
  parseCidr4("127.0.0.0/8"), // row 3: loopback
  parseCidr4("10.0.0.0/8"), // row 2: RFC-1918
  parseCidr4("172.16.0.0/12"), // row 2: RFC-1918
  parseCidr4("192.168.0.0/16"), // row 2: RFC-1918
  // 0.0.0.0/8 is not in the documented matrix but is a well-known real bypass:
  // on Linux, 0.0.0.0 (and the rest of this block) routes to localhost.
  parseCidr4("0.0.0.0/8")
];

const LOCAL_IPV6_CIDRS: Cidr6[] = [
  parseCidr6("::1/128"), // row 5: IPv6 loopback
  parseCidr6("fc00::/7"), // row 5: unique local address (ULA)
  parseCidr6("::/128") // unspecified address, analog of 0.0.0.0
];

const ALWAYS_BLOCKED_IPV4_CIDRS: Cidr4[] = [
  parseCidr4("169.254.0.0/16") // row 1: link-local / cloud metadata
];

const ALWAYS_BLOCKED_IPV6_CIDRS: Cidr6[] = [
  parseCidr6("fe80::/10") // IPv6 link-local, the v6 analog of row 1
];

function unwrapEmbeddedIPv4(groups: number[]): string | null {
  const isMapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
  const isCompatible = groups.slice(0, 6).every((g) => g === 0);
  if (!isMapped && !isCompatible) return null;
  const high = groups[6] ?? 0;
  const low = groups[7] ?? 0;
  return [(high >>> 8) & 0xff, high & 0xff, (low >>> 8) & 0xff, low & 0xff].join(".");
}

function matches(rawIp: string, v4Cidrs: Cidr4[], v6Cidrs: Cidr6[]): boolean {
  const ip = rawIp.startsWith("[") && rawIp.endsWith("]") ? rawIp.slice(1, -1) : rawIp;

  if (isIPv4(ip)) {
    const asInt = ipv4ToInt(ip);
    return v4Cidrs.some((cidr) => isInCidr4(asInt, cidr));
  }

  if (isIPv6(ip)) {
    const groups = expandIPv6Groups(ip);
    if (!groups) return true; // fail closed on unparseable IPv6

    const embeddedIPv4 = unwrapEmbeddedIPv4(groups);
    if (embeddedIPv4 && matches(embeddedIPv4, v4Cidrs, v6Cidrs)) return true;

    const asBigInt = groupsToBigInt(groups);
    return v6Cidrs.some((cidr) => isInCidr6(asBigInt, cidr));
  }

  // Not a recognizable IP literal at all — fail closed.
  return true;
}

/**
 * Validates a single resolved IP address (never a hostname) against every blocked
 * range, including the always-blocked tier. This is the check used when
 * SAFE_FETCH_ALLOW_LOCAL is false. Fails closed on anything unparseable.
 */
export function isBlockedIp(rawIp: string): boolean {
  return (
    matches(rawIp, LOCAL_IPV4_CIDRS, LOCAL_IPV6_CIDRS) ||
    matches(rawIp, ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS)
  );
}

/**
 * Validates against only the never-bypassable tier (link-local / cloud metadata).
 * Callers must run this check unconditionally, even when SAFE_FETCH_ALLOW_LOCAL is
 * true — "let me hit my local dev server" must never imply "let me query cloud
 * instance metadata".
 */
export function isAlwaysBlockedIp(rawIp: string): boolean {
  return matches(rawIp, ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS);
}
