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
});
