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

[`CLAUDE.md`](CLAUDE.md) has the full contributor contract (security invariants, MCP and
TypeScript conventions), including what is out of scope.

## Setup

Requires Node 20+ (the version in `.nvmrc` is the one used for development).

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
