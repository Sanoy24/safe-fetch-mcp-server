# Security

`safe-fetch-mcp-server`'s entire reason to exist is security correctness. This
document is the evidence trail: how it maps against the [OWASP MCP Top
10](https://owasp.org/www-project-mcp-top-10/) (2025), what was fixed as a direct
result of that mapping, and what remains an intentional, documented scope boundary.

For the full SSRF threat matrix and control flow, see
[`.claude/skills/secure-fetch-ssrf/SKILL.md`](.claude/skills/secure-fetch-ssrf/SKILL.md).

## OWASP MCP Top 10 (2025) mapping

| # | Risk | Status | Notes |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ N/A by design | The server holds no credentials of its own. URLs with embedded userinfo (`user:pass@host`) are rejected outright, before any processing — see `urlPolicy.ts`. stdio logging is stderr-only, never stdout (the protocol channel), so nothing can leak into transport traffic. |
| MCP02 | Privilege Escalation via Scope Creep | ✅ N/A by design | One tool (`fetch_url`), read-only (`readOnlyHint: true`, `destructiveHint: false`), fully stateless — there is no session or permission model that could creep. |
| MCP03 | Tool Poisoning | ✅ Mitigated | Single first-party tool, description and schema fully controlled in-repo. No dynamic tool loading. |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | ✅ Mitigated | ADR-004: no third-party IP-classification library is used for the security-critical CIDR/IPv6 logic (the `ip` npm package shipped an SSRF-bypass CVE) — it's hand-written and unit-tested instead. `package-lock.json` is committed for reproducible installs. Small, well-known dependency set (`@modelcontextprotocol/sdk`, `express`, `turndown`, `zod`). |
| MCP05 | Command Injection & Execution | ✅ N/A by design | The server never executes a shell command or spawns a process from any input, ever. |
| MCP06 | Intent Flow Subversion | ✅ Fixed (this pass) | Fetched content is attacker-controllable: any page could contain text engineered to look like instructions to the calling agent. Every successful `fetch_url` response is now framed with an explicit "untrusted data, not instructions" notice (`frameAsUntrustedData` in `tools/fetchUrl.ts`), on every response including paginated chunks. |
| MCP07 | Insufficient Authentication & Authorization | ⚠️ Documented limitation | stdio mode relies on process-level trust (standard for local MCP servers). **HTTP mode has no built-in authentication** — only Origin/Host validation for DNS-rebinding protection, plus per-IP rate limiting (`SAFE_FETCH_RATE_LIMIT_MAX`/`_WINDOW_MS`, default 60 req/min) as a baseline DoS guard. Full auth was never in this project's stated scope (see `PROJECT-1-safe-fetch-mcp-server.md`), and bolting one on unasked would be scope creep. If you deploy HTTP mode over a network, put it behind your own auth layer (reverse proxy, API gateway, VPN) — do not expose it directly. |
| MCP08 | Lack of Audit and Telemetry | ✅ Fixed (this pass) | Every `fetch_url` invocation — allowed or refused — now logs a structured line to stderr with the URL, outcome, and (if refused) the reason, sufficient for SSRF forensics. See `tools/fetchUrl.ts`. |
| MCP09 | Shadow MCP Servers | ℹ️ Organizational, not code | This is a deployment-governance risk, not something the server itself can enforce. If you run this remotely, register it in your org's approved-tool inventory rather than letting it run as an unlisted shadow deployment. |
| MCP10 | Context Injection & Over-Sharing | ✅ N/A by design | Fully stateless: a fresh `McpServer` + transport is created per HTTP request (no session, no shared state across callers), so there is no state for one task/user to leak into another. |

## Threat-matrix validation

Every row of the SSRF threat matrix (cloud metadata, RFC-1918, loopback,
IPv4-mapped IPv6, IPv6 ULA/link-local, encoding bypasses, DNS rebinding,
redirect-to-internal, scheme allowlist, userinfo, resource exhaustion) has a
passing regression test — see `test/ipGuard.spec.ts`, `test/ssrf.spec.ts`,
`test/redirects.spec.ts`.

## External scanner validation

Per ADR-005, validated against [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit)
(276 rules, MIT-licensed, runs fully offline — no code or scan results ever left
this machine), run via `uvx agent-audit-kit scan .` with no persistent install.

**Result: 13 findings → 2, zero critical/high remaining.**

| Run | Critical | High | Medium | Low | Total |
| --- | --- | --- | --- | --- | --- |
| First | 2 | 6 | 4 | 1 | 13 |
| Final | 0 | 0 | 1 | 1 | 2 |

Every finding was individually triaged against the scanner's own rule source
(not just its message text) before being fixed, excluded, or accepted — see
[`.agent-audit-kit.yml`](.agent-audit-kit.yml) for the two documented exclusions.

**Fixed:**

- **AAK-DNS-REBIND-001 (critical)** — the rule pattern-matches for literal tokens
  (`allowedHosts:`, `TrustedHostMiddleware`, ...) in project source and didn't
  recognize the SDK's newer `createMcpExpressApp()` helper, which was already
  providing Host-header protection implicitly. Fixed for real, not just for the
  scanner: `httpApp.ts` now passes `allowedHosts` **explicitly**, which is also
  strictly more robust than the implicit behavior (protection no longer silently
  disables if `HOST` is ever set to something other than the localhost default).
- **AAK-DNS-REBIND-002 (high)** — `@modelcontextprotocol/sdk` was declared as
  `^1.0.0` (the DNS-rebinding fix landed in 1.21.1; 1.30.0 was actually installed,
  but the declared range didn't guarantee that). Tightened to `^1.30.0`.
- **AAK-MCP-018 (medium × 3)** — no rate limiting on the HTTP transport. Added
  `express-rate-limit` (60 req/min per IP by default, configurable), with a
  regression test (`test/httpTransport.spec.ts`) proving a 429 on the 3rd request
  over a 2-request limit.
- **AAK-OAUTH-3P-001 (medium)** — informational nudge to pin and audit the SDK
  dependency; addressed by the same version tightening above.

**Documented risk acceptance** (`.agent-audit-kit.yml`, `accepts_stdio_risk`):

- **AAK-ANTHROPIC-SDK-001 (high)** — targets MCP servers that build shell
  commands/argv from tool input without sanitizing them. This server has no such
  surface: no `child_process`/`execFile`/`spawn`/`exec` anywhere in `src/`.
  `fetch_url`'s only side effect is an HTTP(S) fetch through the hardened
  `security/` guard. Verified, not assumed — see the justification in the config
  file.

**Excluded as false positives** (`.agent-audit-kit.yml`, `exclude-rules`):

- **AAK-AGENT-002 / AAK-AGENT-003 (high × 3)** — keyword matches against
  `CLAUDE.md`'s own defensive security documentation: the string
  `169.254.169.254` (from test-writing guidance telling contributors to prove
  that exact address is refused) and the word "bypassed" (from a sentence
  describing the 2026 CVE this project's single-fetch-path design defends
  against). Removing that language to satisfy a keyword matcher would make the
  documentation worse, not better.

**Remaining, accepted as-is:**

- **AAK-SUPPLY-005 (low)** — 333 lockfile entries exceeds the tool's 200
  threshold. Normal baseline for a modern TS project with eslint +
  typescript-eslint + vitest + express in the dev toolchain; not remediable
  without gutting the toolchain.
- **AAK-OAUTH-3P-001 (medium)** — persists as a generic informational nudge that
  fires for any repo depending on the MCP SDK at all; no OAuth is used anywhere
  in this project.
- Two rate-limiting false triggers on `src/index.ts` and `src/server.ts`
  (per-file keyword heuristic, doesn't see cross-file protection) were closed
  with accurate one-line comments pointing to where the real rate limiter lives
  (`httpApp.ts`) — not scanner-gaming, genuinely useful context either way.

Reproduce: `uvx agent-audit-kit scan . --config .agent-audit-kit.yml --score --owasp-report`
(note: `--score`/`--owasp-report` may crash on Windows consoles with a
`'charmap' codec` error when rendering certain symbols — use `--format json -o <file>`
if that happens; the scan itself still completes and writes correctly).
