---
name: secure-fetch-ssrf
description: The security contract for this server — SSRF, DNS rebinding, redirect, and encoding defenses with the full threat matrix and checklist. Use whenever touching URL handling, DNS resolution, the HTTP client, redirects, or the security/ module.
---

# Secure Fetch / SSRF Defense

This is the security contract. If you change anything that touches URLs, DNS, the HTTP
client, or redirects, re-read this and keep every invariant.

## Core principle

**Allowlist-first, validate the resolved IP, pin the connection.** Hostname string checks
and blocklists fail: IP encodings are effectively infinite and hostnames can rebind. The
only reliable model is: resolve → validate the resolved IP against explicit ranges →
connect to _that same_ IP → re-validate on every redirect.

## Threat → defense matrix

| #   | Attack                    | Example                                    | Defense                                              |
| --- | ------------------------- | ------------------------------------------ | ---------------------------------------------------- |
| 1   | Cloud metadata SSRF       | `http://169.254.169.254/latest/meta-data/` | Block link-local `169.254.0.0/16` on resolved IP     |
| 2   | Private-range SSRF        | `http://10.0.0.5`, `http://192.168.1.1`    | Block RFC-1918 on resolved IP                        |
| 3   | Loopback                  | `http://127.0.0.1`, `http://127.1`         | Block `127.0.0.0/8` after normalization              |
| 4   | IPv4-mapped IPv6 loopback | `http://[::ffff:127.0.0.1]`                | Normalize IPv6, unwrap mapped IPv4, then range-check |
| 5   | IPv6 loopback / ULA       | `http://[::1]`, `fc00::/7`                 | Block on resolved IPv6                               |
| 6   | Encoding bypass           | octal/hex/decimal/dotless IPs              | Validate the resolved IP, not the string             |
| 7   | DNS rebinding             | resolves public then private               | Resolve once, **pin** the connection to that IP      |
| 8   | Redirect-to-internal      | 302 → `http://127.0.0.1`                   | Re-run full validation on **every** hop              |
| 9   | Non-HTTP schemes          | `file://`, `gopher://`, `ftp://`           | Scheme allowlist: `http`, `https` only               |
| 10  | Credentials in URL        | `http://user:pass@host`                    | Strip / reject userinfo                              |
| 11  | Resource exhaustion       | multi-GB body, slow-loris                  | Max-bytes cap + connect/idle/total timeouts          |

## Required control flow

1. Parse the URL. Reject non-http(s) schemes and any userinfo.
2. If an allowlist is configured, the host must match it; otherwise continue to IP checks.
3. Resolve the hostname to IP(s) yourself.
4. Validate **every** resolved IP against the blocked ranges (rows 1–5). Normalize IPv6 and
   unwrap IPv4-mapped addresses before checking.
5. Connect to the **pinned** resolved IP (do not let a high-level client re-resolve).
6. On any redirect, take the `Location`, and go back to step 1 for that URL. Enforce a
   max-redirect count.
7. Stream the body with a hard byte cap and timeouts; mark `truncated` if capped.

## Do NOT

- Do NOT validate the hostname string and then hand the raw hostname to a client that
  re-resolves — that reintroduces DNS rebinding.
- Do NOT trust a single third-party IP-classification library as your only check. One (`ip`)
  shipped an SSRF-bypass CVE. Use explicit CIDR ranges plus regression tests.
- Do NOT create a second fetch path (e.g. a background poller) that skips the guard. This
  was a real 2026 CVE: the initial load was guarded, the recurring poll was not.
- Do NOT follow redirects with a client's built-in auto-follow that bypasses per-hop checks.
- Do NOT expose internal errors; return an actionable refusal message instead.

## Config (safe defaults)

| Env var                    | Default          | Meaning                                               |
| -------------------------- | ---------------- | ----------------------------------------------------- |
| `SAFE_FETCH_ALLOW_LOCAL`   | `false`          | Allow private/loopback targets (opt-in, trusted only) |
| `SAFE_FETCH_ALLOWLIST`     | _(empty)_        | Comma-separated host allowlist                        |
| `SAFE_FETCH_MAX_BYTES`     | e.g. `5_000_000` | Response size cap                                     |
| `SAFE_FETCH_TIMEOUT_MS`    | e.g. `10_000`    | Total request timeout                                 |
| `SAFE_FETCH_MAX_REDIRECTS` | e.g. `5`         | Redirect hop limit                                    |

## Pre-ship checklist

- [ ] Every matrix row has a passing test (see testing skill).
- [ ] Redirects re-validated per hop; max-redirect enforced.
- [ ] Connection pinned to the resolved, validated IP.
- [ ] IPv6 normalized; IPv4-mapped loopback caught.
- [ ] Scheme allowlist + userinfo rejection in place.
- [ ] Size cap + timeouts enforced.
- [ ] No second/unguarded fetch path anywhere in the codebase.
- [ ] Clean result on OWASP MCP Top 10 + a public scanner.
