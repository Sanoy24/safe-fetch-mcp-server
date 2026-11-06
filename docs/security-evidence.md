# Security evidence

How `safe-fetch-mcp-server` maps against the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
(2025), and what automated scanning found. The threat matrix and its tests are in
[`threat-model.md`](threat-model.md). To report a vulnerability, see
[`SECURITY.md`](../SECURITY.md).

Scanners and checklists are a smoke test, not proof of security. What the server does
**not** guarantee is listed in [`threat-model.md`](threat-model.md#not-guaranteed).

## OWASP MCP Top 10 (2025) mapping

| #     | Risk                                                 | Status                      | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----- | ---------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MCP01 | Token Mismanagement & Secret Exposure                | ✅ N/A by design            | The server holds no credentials of its own. URLs with embedded userinfo (`user:pass@host`) are rejected outright, before any processing — see `urlPolicy.ts`. stdio logging is stderr-only, never stdout (the protocol channel), so nothing can leak into transport traffic.                                                                                                                                                                                                                   |
| MCP02 | Privilege Escalation via Scope Creep                 | ✅ N/A by design            | One tool (`fetch_url`), read-only (`readOnlyHint: true`, `destructiveHint: false`), fully stateless — there is no session or permission model that could creep.                                                                                                                                                                                                                                                                                                                                |
| MCP03 | Tool Poisoning                                       | ✅ Mitigated                | Single first-party tool, description and schema fully controlled in-repo. No dynamic tool loading.                                                                                                                                                                                                                                                                                                                                                                                             |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | ✅ Mitigated                | No third-party IP-classification library is used for the security-critical CIDR/IPv6 logic (the `ip` npm package shipped an SSRF-bypass CVE) — it's hand-written and unit-tested instead. `package-lock.json` is committed for reproducible installs, CI fails on any `npm audit` advisory, and Dependabot opens weekly update PRs. Small, well-known dependency set (`@modelcontextprotocol/sdk`, `express`, `turndown`, `zod`).                                                              |
| MCP05 | Command Injection & Execution                        | ✅ N/A by design            | The server never executes a shell command or spawns a process from any input, ever.                                                                                                                                                                                                                                                                                                                                                                                                            |
| MCP06 | Intent Flow Subversion                               | ⚠️ Partially mitigated      | Fetched content is attacker-controllable. Every successful `fetch_url` response is framed with an explicit "untrusted data, not instructions" notice (`frameAsUntrustedData` in `tools/fetchUrl.ts`), including paginated chunks. A label does not stop a model from following injected text: the consuming application still needs its own prompt-injection defenses.                                                                                                                         |
| MCP07 | Insufficient Authentication & Authorization          | ⚠️ Documented limitation    | stdio mode relies on process-level trust (standard for local MCP servers). **HTTP mode has no built-in authentication** — only Origin/Host validation for DNS-rebinding protection, plus per-IP rate limiting (`SAFE_FETCH_RATE_LIMIT_MAX`/`_WINDOW_MS`, default 60 req/min) as a baseline DoS guard. Authentication is out of scope for this server. If you deploy HTTP mode over a network, put it behind your own auth layer (reverse proxy, API gateway, VPN) — do not expose it directly. |
| MCP08 | Lack of Audit and Telemetry                          | ✅ Mitigated                | Every `fetch_url` invocation — allowed or refused — now logs a structured line to stderr with the URL, outcome, and (if refused) the reason, sufficient for SSRF forensics. Resolved addresses and socket errors appear only in this log, never in the result returned to the model. See `tools/fetchUrl.ts`.                                                                                                                                                                                  |
| MCP09 | Shadow MCP Servers                                   | ℹ️ Organizational, not code | This is a deployment-governance risk, not something the server itself can enforce. If you run this remotely, register it in your org's approved-tool inventory rather than letting it run as an unlisted shadow deployment.                                                                                                                                                                                                                                                                    |
| MCP10 | Context Injection & Over-Sharing                     | ✅ N/A by design            | Fully stateless: a fresh `McpServer` + transport is created per HTTP request (no session, no shared state across callers), so there is no state for one task/user to leak into another.                                                                                                                                                                                                                                                                                                        |

## Threat-matrix validation

Every row of the threat matrix has a regression test. The mapping from row to spec file is
in [`threat-model.md`](threat-model.md#threat-matrix).

## External scanner validation

_Run on 6 November 2026 with [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit) 0.6.31
(440 rules), on a clean checkout of v0.6.0 and then of the fix below. Re-run before quoting these
numbers for a later release._

The scan runs offline, and clean checkouts keep local, untracked files out of the result.

| Run                 | Critical | High | Medium | Low | Total reported |
| ------------------- | -------- | ---- | ------ | --- | -------------- |
| v0.6.0              | 1        | 5    | 6      | 5   | 17             |
| After the fix below | 0        | 5    | 6      | 5   | 16             |

**The result isn't clean: the five remaining highs are still reported.** Each was checked against the
code and is a false positive. They're listed here rather than excluded in the config, because an
exclusion would also hide a real finding from the same rule later.

### Fixed: a real vulnerability

**AAK-RUNTIME-ADV-001 (critical): Node's Brotli decoder (CVE-2026-111497).** Confirmed in Node's
release notes, which rate it High. This server decompresses what sites send, so a hostile page could
reach the out-of-bounds write on an unpatched Node, and `engines` allowed unpatched versions. Now, on
an affected Node, the server neither offers nor decodes Brotli and warns at startup, and `engines`
requires a patched release. See threat-model row 33.

### False positives (high)

| Finding                                     | Where                                                | Why it doesn't apply                                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AAK-SECRET-004, high-entropy secret         | `src/config.ts`                                      | The match is the variable name `httpToken`. The value comes from `SAFE_FETCH_HTTP_TOKEN` at runtime, and no secret is in the repo                            |
| AAK-MCP-014, token in a URL (twice)         | `test/auditLog.spec.ts`, `test/toolContract.spec.ts` | Test fixtures proving that query values are redacted from the audit log. The server's token is a header only                                                 |
| AAK-SSRF-002, loopback reachable            | `test/httpHardening.spec.ts`                         | A test connecting to its own local fixture. The tool's guard refuses loopback unless `SAFE_FETCH_ALLOW_LOCAL` is set, as `test/vectors.spec.ts` covers       |
| AAK-MCP-TOOLGATE-ASYMMETRY-001, hidden tool | `test/compat.spec.ts`                                | The optional `fetch` tool isn't registered at all when off, so there's nothing to call. `test/compat.spec.ts` checks that a direct call fails with not found |

### Medium and low

| Finding                                         | Status         | Reason                                                                                                                                          |
| ----------------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| AAK-MCP-005, AAK-MCP-007, npx without a version | Accepted       | The example config uses the install method most clients document. Pin `safe-fetch-mcp-server@x.y.z` if you want updates to be a deliberate step |
| AAK-MCP-ATTEST-001, no attestation              | Accepted       | Concerns the host's server admission. npm provenance is published for each release                                                              |
| AAK-COMPOSE-003, skill capabilities             | Accepted       | The skill tells an agent how to use this server's tool. It has no scripts of its own                                                            |
| AAK-OAUTH-3P-001, depends on an MCP SDK         | Accepted       | Fires for any MCP project. This project uses no OAuth                                                                                           |
| AAK-OAUTH-008, no OAuth discovery (twice)       | Accepted       | HTTP mode has a static bearer token, not OAuth, as the threat model states                                                                      |
| AAK-SUPPLY-005, 279 lockfile entries            | Accepted       | Most are development tools. The limit is the scanner's own threshold of 200                                                                     |
| AAK-STARTUP-HOOK-NPM-INSTALL-001, fsevents      | Accepted       | An optional, development-only, macOS-only package. Nothing with an install script is in the published dependencies                              |
| AAK-MCP-018, no rate limit                      | False positive | A test file. The limit is in `src/httpApp.ts`, and `test/httpTransport.spec.ts` covers it                                                       |
| AAK-MCP-TOOLS-LIST-UNBOUNDED-001                | False positive | The smoke test reading the tool list of the package it just built                                                                               |

### Reproduce

```bash
git clone https://github.com/Sanoy24/safe-fetch-mcp-server.git && cd safe-fetch-mcp-server
uvx agent-audit-kit scan . --config .agent-audit-kit.yml --format json -o result.json
```

On Windows, set `PYTHONUTF8=1` first if the console reports a `charmap` error.

An earlier scan of v0.1.0, with 276 rules, went from 13 findings to 2 after fixes. Its details are in
this file's git history.
