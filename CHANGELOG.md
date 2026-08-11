# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-08-11

### Added

- `server.json` and `mcpName` (`io.github.sanoy24/safe-fetch`) for submission
  to the official [MCP Registry](https://registry.modelcontextprotocol.io).
  No functional changes.

## [0.1.1] - 2026-08-11

### Fixed

- README: removed a stale "pre-publish, not yet on npm" status note that was
  wrong as soon as 0.1.0 published, and replaced the Mermaid architecture
  diagram (unrendered raw syntax on the npm registry page — npm's README
  renderer doesn't support Mermaid, unlike GitHub) with a plain numbered
  pipeline description that renders correctly everywhere.
- README: added npm version / CI / license / Node engines badges now that the
  repository is public and links resolve.

## [0.1.0] - 2026-08-11

### Added

- `fetch_url` MCP tool: fetches an `http(s)` URL and returns clean markdown
  (or raw text), with `structuredContent` (`status`, `finalUrl`, `contentType`,
  `bytes`, `truncated`) and chunked reading via `start_index`.
- SSRF defense (`src/security/`): allowlist-first, resolve-once-and-pin,
  re-validate-every-redirect-hop. Blocks loopback, RFC-1918, link-local /
  cloud metadata (always, even with `SAFE_FETCH_ALLOW_LOCAL=true`), IPv6
  ULA/link-local, IPv4-mapped IPv6, non-http(s) schemes, and embedded
  userinfo. No third-party IP-classification library — hand-written CIDR/IPv6
  parsing with full regression coverage (see `test/ipGuard.spec.ts`).
- Connection pinning via a custom DNS `lookup` hook on `node:http`/`node:https`,
  specifically to avoid the TOCTOU gap where Node's global `fetch`/undici
  re-resolves DNS at connect time and silently defeats prior IP validation.
- stdio transport (default) and Streamable HTTP transport (`--http` flag or
  `TRANSPORT=http`), stateless per the MCP spec.
- HTTP transport hardening: explicit Host-header allow-list (DNS-rebinding
  protection), Origin validation with CORS support for explicitly allowlisted
  origins, and per-IP rate limiting (`express-rate-limit`, 60 req/min default).
- Untrusted-content framing: every successful `fetch_url` response explicitly
  marks fetched content as data, not instructions (OWASP MCP06:2025 mitigation).
- Structured audit logging to stderr for every fetch outcome, allowed or
  refused (OWASP MCP08:2025 mitigation).
- Full threat-matrix test suite (62 tests) covering every SSRF row, redirect
  re-validation, the "poller" guard-bypass regression, HTTP transport security,
  and content conversion.
- External validation via [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit):
  13 findings → 2, zero critical/high remaining. See `SECURITY.md`.

[0.1.2]: https://github.com/sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.2
[0.1.1]: https://github.com/sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.1
[0.1.0]: https://github.com/sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.0
