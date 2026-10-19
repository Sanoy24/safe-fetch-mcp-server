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

// Row references are to the threat matrix in docs/threat-model.md.
// Ranges come from the IANA IPv4/IPv6 Special-Purpose Address Registries.
//
// Every address falls into exactly one of three classes, deliberately:
//   - "forbidden": cloud metadata, link-local, multicast, reserved. Never a
//     legitimate fetch target and never something "local dev access" should imply.
//     Not bypassable by SAFE_FETCH_ALLOW_LOCAL. Checked first, so a forbidden /32
//     inside a private range (e.g. 100.100.100.200 inside 100.64.0.0/10) wins.
//   - "private": loopback, RFC-1918, ULA and other non-global space. Blocked by
//     default; SAFE_FETCH_ALLOW_LOCAL opts into it for a trusted local target.
//   - "public": everything else for IPv4; only global unicast (2000::/3) for IPv6.
export type IpClass = "public" | "private" | "forbidden";

const FORBIDDEN_IPV4_CIDRS: Cidr4[] = [
  parseCidr4("169.254.0.0/16"), // row 1: link-local / AWS, GCP, Azure, OCI metadata
  parseCidr4("100.100.100.200/32"), // row 1: Alibaba Cloud metadata
  parseCidr4("224.0.0.0/4"), // multicast
  parseCidr4("240.0.0.0/4") // reserved, includes broadcast 255.255.255.255
];

const PRIVATE_IPV4_CIDRS: Cidr4[] = [
  parseCidr4("127.0.0.0/8"), // row 3: loopback
  parseCidr4("10.0.0.0/8"), // row 2: RFC-1918
  parseCidr4("172.16.0.0/12"), // row 2: RFC-1918
  parseCidr4("192.168.0.0/16"), // row 2: RFC-1918
  // 0.0.0.0/8 is not in the documented matrix but is a well-known real bypass:
  // on Linux, 0.0.0.0 (and the rest of this block) routes to localhost.
  parseCidr4("0.0.0.0/8"),
  parseCidr4("100.64.0.0/10"), // CGNAT / shared address space (often internal on clouds)
  parseCidr4("192.0.0.0/24"), // IETF protocol assignments
  parseCidr4("192.0.2.0/24"), // TEST-NET-1
  parseCidr4("198.18.0.0/15"), // benchmarking
  parseCidr4("198.51.100.0/24"), // TEST-NET-2
  parseCidr4("203.0.113.0/24") // TEST-NET-3
];

const FORBIDDEN_IPV6_CIDRS: Cidr6[] = [
  parseCidr6("fe80::/10"), // IPv6 link-local, the v6 analog of row 1
  parseCidr6("fd00:ec2::254/128"), // row 1: AWS IMDS over IPv6 (inside ULA, so checked first)
  parseCidr6("ff00::/8") // multicast
];

const PRIVATE_IPV6_CIDRS: Cidr6[] = [
  parseCidr6("::1/128"), // row 5: IPv6 loopback
  parseCidr6("fc00::/7"), // row 5: unique local address (ULA)
  parseCidr6("::/128"), // unspecified address, analog of 0.0.0.0
  // Inside 2000::/3 but not globally reachable:
  parseCidr6("2001::/32"), // Teredo (embeds an obfuscated IPv4)
  parseCidr6("2001:db8::/32") // documentation
];

const GLOBAL_UNICAST_IPV6: Cidr6 = parseCidr6("2000::/3");

function groupsToIPv4(high: number, low: number): string {
  return [(high >>> 8) & 0xff, high & 0xff, (low >>> 8) & 0xff, low & 0xff].join(".");
}

/**
 * Returns the IPv4 address embedded in an IPv6 address by a translation or
 * transition mechanism, so it can be range-checked as IPv4: IPv4-mapped
 * (::ffff:0:0/96), IPv4-compatible (::/96), NAT64 well-known prefix (64:ff9b::/96)
 * and 6to4 (2002::/16, IPv4 in bits 16-47). Without this, 64:ff9b::a9fe:a9fe
 * reaches 169.254.169.254 on any network with a NAT64 gateway.
 */
function unwrapEmbeddedIPv4(groups: number[]): string | null {
  const g = (i: number): number => groups[i] ?? 0;
  const zeroFrom1To4 = g(1) === 0 && g(2) === 0 && g(3) === 0 && g(4) === 0;

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
  if (g(0) === 0 && zeroFrom1To4 && (g(5) === 0xffff || g(5) === 0)) {
    return groupsToIPv4(g(6), g(7));
  }
  // NAT64 well-known prefix (64:ff9b::a.b.c.d)
  if (
    g(0) === 0x64 &&
    g(1) === 0xff9b &&
    g(2) === 0 &&
    g(3) === 0 &&
    g(4) === 0 &&
    g(5) === 0
  ) {
    return groupsToIPv4(g(6), g(7));
  }
  // 6to4 (2002:aabb:ccdd::/48)
  if (g(0) === 0x2002) return groupsToIPv4(g(1), g(2));
  return null;
}

function classifyIPv4(ip: string): IpClass {
  const asInt = ipv4ToInt(ip);
  if (FORBIDDEN_IPV4_CIDRS.some((cidr) => isInCidr4(asInt, cidr))) return "forbidden";
  if (PRIVATE_IPV4_CIDRS.some((cidr) => isInCidr4(asInt, cidr))) return "private";
  return "public";
}

function classifyIPv6(ip: string): IpClass {
  const groups = expandIPv6Groups(ip);
  if (!groups) return "forbidden"; // fail closed on unparseable IPv6

  const asBigInt = groupsToBigInt(groups);
  if (FORBIDDEN_IPV6_CIDRS.some((cidr) => isInCidr6(asBigInt, cidr))) return "forbidden";

  const embeddedIPv4 = unwrapEmbeddedIPv4(groups);
  if (embeddedIPv4) {
    // ::1 and :: are IPv4-compatible in form but are IPv6 loopback/unspecified;
    // both classify as private either way, so no special case is needed.
    return classifyIPv4(embeddedIPv4);
  }

  if (PRIVATE_IPV6_CIDRS.some((cidr) => isInCidr6(asBigInt, cidr))) return "private";
  // Only global unicast is public; anything else (site-local, discard-only,
  // unassigned space, NAT64 local-use 64:ff9b:1::/48, ...) is non-global.
  return isInCidr6(asBigInt, GLOBAL_UNICAST_IPV6) ? "public" : "private";
}

/**
 * Classifies a single resolved IP address (never a hostname). Anything that is not
 * a recognizable IPv4/IPv6 literal is "forbidden" — fail closed.
 */
export function classifyIp(rawIp: string): IpClass {
  const ip = rawIp.startsWith("[") && rawIp.endsWith("]") ? rawIp.slice(1, -1) : rawIp;
  const zoneless = ip.includes("%") ? ip.slice(0, ip.indexOf("%")) : ip;
  if (isIPv4(zoneless)) return classifyIPv4(zoneless);
  if (isIPv6(ip)) return classifyIPv6(ip);
  return "forbidden";
}

/**
 * True for every non-public address, including the forbidden tier. This is the
 * check used when SAFE_FETCH_ALLOW_LOCAL is false.
 */
export function isBlockedIp(rawIp: string): boolean {
  return classifyIp(rawIp) !== "public";
}

/**
 * True only for the never-bypassable tier (metadata, link-local, multicast,
 * reserved). Callers must run this check unconditionally, even when
 * SAFE_FETCH_ALLOW_LOCAL is true — "let me hit my local dev server" must never
 * imply "let me query cloud instance metadata".
 */
export function isAlwaysBlockedIp(rawIp: string): boolean {
  return classifyIp(rawIp) === "forbidden";
}
