import { describe, it, expect } from "vitest";
import { isBlockedIp, isAlwaysBlockedIp } from "../src/security/ipGuard.js";

describe("ipGuard (pure, no network)", () => {
  it("blocks the cloud metadata endpoint", () => {
    expect(isBlockedIp("169.254.169.254")).toBe(true);
  });

  it("blocks RFC-1918 private ranges", () => {
    expect(isBlockedIp("10.0.0.5")).toBe(true);
    expect(isBlockedIp("172.16.5.9")).toBe(true);
    expect(isBlockedIp("192.168.1.1")).toBe(true);
  });

  it("blocks IPv4 loopback", () => {
    expect(isBlockedIp("127.0.0.1")).toBe(true);
    expect(isBlockedIp("127.5.6.7")).toBe(true); // whole 127.0.0.0/8
  });

  it("blocks 0.0.0.0/8 (routes to localhost on Linux)", () => {
    expect(isBlockedIp("0.0.0.1")).toBe(true);
  });

  it("allows a normal public IPv4 address", () => {
    expect(isBlockedIp("93.184.216.34")).toBe(false);
  });

  it("blocks IPv6 loopback", () => {
    expect(isBlockedIp("::1")).toBe(true);
  });

  it("blocks IPv6 unique-local addresses (ULA)", () => {
    expect(isBlockedIp("fc00::1")).toBe(true);
    expect(isBlockedIp("fd12:3456:789a::1")).toBe(true);
  });

  it("blocks IPv6 link-local addresses", () => {
    expect(isBlockedIp("fe80::1")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)", () => {
    expect(isBlockedIp("::ffff:127.0.0.1")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6 metadata address", () => {
    expect(isBlockedIp("::ffff:169.254.169.254")).toBe(true);
  });

  it("blocks the deprecated IPv4-compatible IPv6 form (::127.0.0.1)", () => {
    expect(isBlockedIp("::127.0.0.1")).toBe(true);
  });

  it("does NOT blanket-block IPv4-mapped IPv6 for a public address", () => {
    // Regression guard: only the unwrapped IPv4 should be range-checked, not the
    // whole ::ffff:0:0/96 block indiscriminately.
    expect(isBlockedIp("::ffff:8.8.8.8")).toBe(false);
  });

  it("allows a normal public IPv6 address", () => {
    expect(isBlockedIp("2001:4860:4860::8888")).toBe(false);
  });

  it("fails closed on unparseable input", () => {
    expect(isBlockedIp("not-an-ip")).toBe(true);
  });
});

describe("isAlwaysBlockedIp (never bypassable, even with ALLOW_LOCAL=true)", () => {
  it("blocks metadata / link-local IPv4", () => {
    expect(isAlwaysBlockedIp("169.254.169.254")).toBe(true);
  });

  it("blocks IPv6 link-local", () => {
    expect(isAlwaysBlockedIp("fe80::1")).toBe(true);
  });

  it("blocks IPv4-mapped metadata", () => {
    expect(isAlwaysBlockedIp("::ffff:169.254.169.254")).toBe(true);
  });

  it("does NOT block loopback or RFC-1918 (those are the bypassable tier)", () => {
    expect(isAlwaysBlockedIp("127.0.0.1")).toBe(false);
    expect(isAlwaysBlockedIp("10.0.0.5")).toBe(false);
    expect(isAlwaysBlockedIp("192.168.1.1")).toBe(false);
  });

  it("does not block public addresses", () => {
    expect(isAlwaysBlockedIp("93.184.216.34")).toBe(false);
  });

  it("blocks Alibaba Cloud metadata (100.100.100.200), even inside the CGNAT range", () => {
    expect(isAlwaysBlockedIp("100.100.100.200")).toBe(true);
    expect(isAlwaysBlockedIp("::ffff:100.100.100.200")).toBe(true);
  });

  it("blocks AWS IPv6 IMDS (fd00:ec2::254), even though it sits inside ULA", () => {
    expect(isAlwaysBlockedIp("fd00:ec2::254")).toBe(true);
    // Neighbouring ULA addresses stay in the bypassable tier.
    expect(isAlwaysBlockedIp("fd00:ec2::253")).toBe(false);
  });

  it("blocks multicast, reserved and broadcast (never a legitimate fetch target)", () => {
    expect(isAlwaysBlockedIp("224.0.0.1")).toBe(true);
    expect(isAlwaysBlockedIp("239.255.255.250")).toBe(true);
    expect(isAlwaysBlockedIp("240.0.0.1")).toBe(true);
    expect(isAlwaysBlockedIp("255.255.255.255")).toBe(true);
    expect(isAlwaysBlockedIp("ff02::1")).toBe(true);
  });

  it("unwraps NAT64 and 6to4 to catch embedded metadata addresses", () => {
    expect(isAlwaysBlockedIp("64:ff9b::a9fe:a9fe")).toBe(true); // 169.254.169.254
    expect(isAlwaysBlockedIp("2002:a9fe:a9fe::1")).toBe(true); // 169.254.169.254
  });
});

describe("ipGuard — special-purpose ranges (IANA registries)", () => {
  it("blocks CGNAT / shared address space 100.64.0.0/10", () => {
    expect(isBlockedIp("100.64.0.1")).toBe(true);
    expect(isBlockedIp("100.127.255.254")).toBe(true);
    expect(isBlockedIp("100.128.0.1")).toBe(false); // just outside the /10
  });

  it("blocks IETF protocol, benchmarking and documentation IPv4 ranges", () => {
    expect(isBlockedIp("192.0.0.1")).toBe(true);
    expect(isBlockedIp("198.18.0.1")).toBe(true);
    expect(isBlockedIp("198.19.255.254")).toBe(true);
    expect(isBlockedIp("192.0.2.1")).toBe(true);
    expect(isBlockedIp("198.51.100.1")).toBe(true);
    expect(isBlockedIp("203.0.113.1")).toBe(true);
    expect(isBlockedIp("198.20.0.1")).toBe(false); // just outside 198.18.0.0/15
  });

  it("blocks NAT64 (64:ff9b::/96) addresses that embed a private IPv4", () => {
    expect(isBlockedIp("64:ff9b::7f00:1")).toBe(true); // 127.0.0.1
    expect(isBlockedIp("64:ff9b::a00:5")).toBe(true); // 10.0.0.5
  });

  it("allows NAT64 addresses that embed a public IPv4 (DNS64 on IPv6-only hosts)", () => {
    expect(isBlockedIp("64:ff9b::808:808")).toBe(false); // 8.8.8.8
  });

  it("blocks 6to4 (2002::/16) addresses that embed a private IPv4", () => {
    expect(isBlockedIp("2002:7f00:1::1")).toBe(true); // 127.0.0.1
    expect(isBlockedIp("2002:c0a8:101::1")).toBe(true); // 192.168.1.1
    expect(isBlockedIp("2002:808:808::1")).toBe(false); // 8.8.8.8
  });

  it("allows only global unicast IPv6 (2000::/3) by default", () => {
    expect(isBlockedIp("fec0::1")).toBe(true); // deprecated site-local
    expect(isBlockedIp("100::1")).toBe(true); // discard-only
    expect(isBlockedIp("2001:db8::1")).toBe(true); // documentation
    expect(isBlockedIp("2001::1")).toBe(true); // Teredo
    expect(isBlockedIp("4000::1")).toBe(true); // unassigned, outside 2000::/3
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
  });
});
