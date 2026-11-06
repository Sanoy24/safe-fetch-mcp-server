# Contributing

Thanks for helping. This project exists for one reason, which is to be correct about outbound
request security. Contributions are judged by that standard first.

## Ground rules

- **Every outbound request goes through `safeFetch` in `src/security/`.** Don't add a second
  fetch path, a cache that skips validation, or a "just this once" bypass.
- **Security changes are test-first.** Write a failing test that proves the gap, then fix it.
  Use local fixtures and fake resolvers, never real internal or third-party targets.
- **Don't weaken a control to make a test or a client work.** Open an issue instead.
- Found a vulnerability? **Don't open a public issue.** See [`SECURITY.md`](SECURITY.md).

## Security invariants

These are the rules the guard exists to enforce. The attacks behind them are in
[`docs/threat-model.md`](docs/threat-model.md).

1. Validate the **resolved IP**, never the hostname string. IP encodings are endless, so hostname
   blocklists fail.
2. **Pin the connection** to the validated addresses, with one resolution, to defeat DNS rebinding.
3. **Re-validate every redirect hop** with the full guard. A 302 to `127.0.0.1` must be refused.
4. Allow only the `http` and `https` schemes.
5. Reject credentials in URLs (`user:pass@`).
6. Enforce the response size limit and the total deadline.
7. Check explicit CIDR ranges, with regression tests. Don't rely on a single third-party
   IP-classification library: one had an SSRF CVE of its own.
8. Keep `SAFE_FETCH_ALLOW_LOCAL` off by default. Local access is opt-in only, and cloud metadata
   is never allowed.

## Code conventions

- **MCP:** use `server.registerTool()`. Give every tool a title, description, annotations, and a
  strict Zod input schema with `.describe()` on each field. Return `content` and
  `structuredContent`.
- **Errors:** return them in the result with `isError: true` and a message that says what to do.
  Never expose stack traces, internal paths or resolved addresses. Those go in the audit log.
- **Logging:** use stderr only (`console.error`), because stdout carries MCP traffic in stdio mode.
- **TypeScript:** strict mode with no `any`. Use `unknown` with type guards, and write explicit
  `Promise<T>` return types on async functions.

## Out of scope

- A browser or JavaScript-rendering scraper. That's a different kind of tool.
- A scanner for other MCP servers. This project uses scanners rather than building them.

## Setup

Requires Node 22.23.4+, 24.22.1+ or 26.12.1+ (the version in `.nvmrc` is the one used for development).

```bash
npm ci
npm run check       # format:check → lint → typecheck → build → test (same as CI)
```

Other scripts:

| Script               | Purpose                                                   |
| -------------------- | --------------------------------------------------------- |
| `npm run dev`        | Rebuild on change                                         |
| `npm run test:watch` | Vitest in watch mode                                      |
| `npm run format`     | Apply Prettier                                            |
| `npm run inspector`  | Build and open the MCP Inspector against the stdio server |
| `npm run start:http` | Run Streamable HTTP on `127.0.0.1:3000/mcp`               |

## Adding a security regression test

1. Pick the spec that matches the layer: `test/ipGuard.spec.ts` (pure IP classification),
   `test/ssrf.spec.ts` (URL + DNS guard), `test/redirects.spec.ts` (per-hop), or
   `test/httpTransport.spec.ts` (HTTP mode).
2. Assert the **specific** refusal, not just that something threw. Otherwise a DNS failure can
   make an IP-guard test pass for the wrong reason.
3. If you add a blocked range, add one positive (blocked) and one adjacent negative (allowed)
   case.

## Pull requests

- Keep each PR to one concern. Formatting-only changes go in their own PR.
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`fix:`, `feat:`, `docs:`,
  `chore:`, `test:`).
- Update `CHANGELOG.md` under `## [Unreleased]` when behaviour or tool output changes.
