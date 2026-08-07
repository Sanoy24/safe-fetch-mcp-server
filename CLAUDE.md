# CLAUDE.md — safe-fetch-mcp-server

Context for Claude Code (and humans) working in this repo. Read this before writing code.

## What this project is

An MCP server that fetches web content for an agent and returns clean markdown. Its reason
to exist is **security correctness**: it must be safe-by-default against SSRF, DNS rebinding,
redirect-to-internal, and encoding bypasses — the exact classes that produced real 2026 CVEs
in other fetch servers. "Has SSRF protection" is not the bar; "provably correct, verified by
the OWASP MCP Top 10 and public scanners" is.

## The one rule that matters most

**Every outbound request MUST pass through the `security/` guard. No code path may fetch a
URL without it.** The most common real-world failure (a 2026 CVE) was a poller that
re-fetched a URL and bypassed the guard applied on first load. Do not introduce a second
fetch path. If you need to fetch, call the single hardened fetch function.

## Non-negotiable security invariants

1. Validate the **resolved IP**, never the hostname string. IP encodings are infinite;
   hostname blocklists fail.
2. **Pin the connection** to the resolved IP (resolve once, connect to that IP) to defeat
   DNS rebinding.
3. **Re-validate every redirect hop** with the full guard — a 302 to `127.0.0.1` must be
   rejected.
4. Scheme allowlist: `http` and `https` only. Reject `file:`, `gopher:`, `ftp:`, etc.
5. Strip/reject URL userinfo (`user:pass@`).
6. Enforce max response bytes and connect/idle/total timeouts.
7. Block on the resolved IP: loopback `127.0.0.0/8` + `::1`, private RFC-1918, link-local
   `169.254.0.0/16` (metadata!), ULA `fc00::/7`, and IPv4-mapped IPv6 loopback
   (`::ffff:127.0.0.1`).
8. Default `SAFE_FETCH_ALLOW_LOCAL=false`. Local access is opt-in only.

See `.claude/skills/secure-fetch-ssrf/SKILL.md` for the full checklist and threat matrix.

## Architecture

```
Agent → MCP client → fetch_url tool → security guard → pinned fetch → markdown → result
```

- `src/index.ts` — entrypoint, chooses transport (stdio default, HTTP if TRANSPORT=http).
- `src/server.ts` — McpServer + tool registration.
- `src/tools/fetchUrl.ts` — the `fetch_url` tool.
- `src/security/` — urlPolicy, ipGuard, resolveAndPin, redirects. The guard lives here.
- `src/content/toMarkdown.ts` — HTML → clean markdown.
- `src/config.ts` — env parsing + defaults.
- `test/` — one spec per threat-matrix row.

## MCP conventions (current SDK — do not use deprecated APIs)

- Use `server.registerTool(...)`. **Do NOT** use `server.tool()` or manual
  `setRequestHandler`.
- Input schemas are **Zod** with `.strict()`, constraints, and `.describe()` on every field.
- Provide `title`, `description`, `inputSchema`, and `annotations` for every tool.
- `fetch_url` annotations: `readOnlyHint: true`, `destructiveHint: false`,
  `idempotentHint: true`, `openWorldHint: true`.
- Return both `content` (text) and `structuredContent` (status, finalUrl, contentType,
  bytes, truncated).
- Errors: return inside the result with `isError: true` and an **actionable** message.
  Never leak stack traces or internal paths.
- **stdio logging goes to stderr only** (stdout carries MCP traffic). Use `console.error`.

See `.claude/skills/writing-mcp-servers/SKILL.md`.

## TypeScript conventions

- Strict mode on. **No `any`** — use `unknown` + type guards.
- Explicit `Promise<T>` return types on async functions.
- DRY: one shared fetch function, one shared error formatter. Never duplicate the guard.

## Commands

```bash
npm install            # install deps (verify SDK version on first run)
npm run build          # tsc → dist/
npm run dev            # watch mode
npm start              # run compiled server (stdio)
TRANSPORT=http npm start   # run over Streamable HTTP
npm test               # vitest — all SSRF specs must pass
npm run lint           # eslint
npm run format         # prettier
npm run inspector      # npx @modelcontextprotocol/inspector for manual testing
```

## Testing workflow (see testing skill)

1. Write the failing test first (e.g. a fetch of `http://169.254.169.254/` must be refused).
2. Implement the guard until it passes.
3. Every row in the threat matrix has its own passing test before shipping.
4. Run the MCP Inspector to sanity-check tool schemas.
5. Run external scanners (OWASP MCP Top 10, AgentAuditKit, MCPSafe) and capture a clean
   result for the README.

## Definition of done

- `npx safe-fetch-mcp-server` runs in a clean environment, no build step for the user.
- `npm run build` and `npm run lint` are clean; `npm test` is green with a test per threat row.
- Clean result on OWASP MCP Top 10 + at least one public scanner, evidenced in README.
- README has an `npx` config block and a demo GIF of an SSRF **refusal**.
- Published to npm and submitted to the MCP registry; CI green.

## Things NOT to do

- Do not add a browser/JS-rendering scraper (out of scope; different category).
- Do not add a second fetch path or bypass the guard "just for this one case".
- Do not trust a single third-party IP-classification library alone (one had an SSRF CVE);
  validate against explicit CIDR ranges with regression tests.
- Do not build a scanner for other servers (saturated; we consume scanners, not build them).
