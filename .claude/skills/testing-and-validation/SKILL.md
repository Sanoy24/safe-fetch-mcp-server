---
name: testing-and-validation
description: How to test and validate this MCP server — unit tests for every SSRF threat, MCP Inspector checks, and external scanner validation. Use when writing tests, before shipping, or when verifying security correctness.
---

# Testing & Validation

Testing here is security testing. A fetch server that "works" is not enough — it must
provably **refuse** the dangerous cases. Ordinary AI-generated tests only assert that valid
URLs succeed; they never assert that internal targets are refused. Those refusals are the
whole point.

## 1. Test-first, one test per threat

Write the failing test before the guard exists, then implement until green. There must be a
test for **every row** of the threat matrix in the security skill. Minimum set:

- Refuse `http://169.254.169.254/latest/meta-data/` (cloud metadata).
- Refuse loopback `http://127.0.0.1`, `http://127.1`.
- Refuse private ranges `http://10.0.0.5`, `http://192.168.1.1`.
- Refuse IPv4-mapped IPv6 loopback `http://[::ffff:127.0.0.1]`.
- Refuse IPv6 loopback/ULA `http://[::1]`.
- Refuse encoded IPs (octal/hex/decimal/dotless variants).
- Refuse a redirect whose next hop is internal (302 → `http://127.0.0.1`).
- Refuse non-http(s) schemes (`file:`, `gopher:`, `ftp:`).
- Refuse URLs with userinfo (`http://user:pass@host`).
- Enforce max-bytes truncation and timeouts.
- **Regression: a re-fetch / poller path also goes through the guard** (the 2026 bypass).
- Allow a normal public URL and return clean markdown.

### Example (Vitest)

```ts
import { describe, it, expect } from 'vitest';
import { assertSafeUrl } from '../src/security/index.js';

describe('SSRF guard', () => {
    it('refuses the cloud metadata endpoint', async () => {
        await expect(
            assertSafeUrl('http://169.254.169.254/latest/meta-data/'),
        ).rejects.toThrow();
    });

    it('refuses IPv4-mapped IPv6 loopback', async () => {
        await expect(
            assertSafeUrl('http://[::ffff:127.0.0.1]/'),
        ).rejects.toThrow();
    });

    it('re-validates each redirect hop', async () => {
        // Spin up a local server that 302s to http://127.0.0.1 and assert the fetch is refused.
    });

    it('allows a normal public URL', async () => {
        await expect(
            assertSafeUrl('https://example.com'),
        ).resolves.toBeTruthy();
    });
});
```

Test the guard directly (unit) _and_ through the `fetch_url` tool (integration), so a future
refactor can't route around it.

## 2. MCP Inspector (manual protocol check)

```bash
npm run inspector
```

Verify: the tool lists with the right `title`/`description`/annotations, the Zod schema
rejects bad input, a good URL returns text + `structuredContent`, and a blocked URL returns
`isError: true` with an actionable message.

## 3. External scanner validation (the headline proof)

Do NOT build your own scanner — run the established ones and aim for a clean result:

- **OWASP MCP Top 10** — the reference checklist; map each item to a pass.
- **AgentAuditKit** — SSRF redirect-bypass, DNS-rebinding, transport, config rules.
- **MCPSafe** / **badchars/mcp-security-scanner** — SAST for SSRF/injection/secrets.

Capture a clean score (screenshot / SARIF) for the README — third-party validation is a
stronger claim than a homegrown suite. Optionally gate CI on a scan (see `ci.yml`).

## 4. Standard testing layers

- **Functional**: valid and invalid inputs behave correctly.
- **Integration**: redirects, timeouts, large bodies, content-type handling.
- **Security**: the whole threat matrix (above).
- **Build gate**: `npm run build`, `npm run lint`, `npm test` all clean before shipping.

## Definition of done (testing)

- A passing test exists for every threat-matrix row, including the poller/redirect regression.
- `fetch_url` verified in the MCP Inspector.
- Clean result on OWASP MCP Top 10 + at least one scanner, evidenced in the README.
- CI green on all supported Node versions.
