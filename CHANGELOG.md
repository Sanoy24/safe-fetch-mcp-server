# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-19

### Added

- Stable error codes: failures return `structuredContent.error = { code, retryable }`
  (`POLICY_REJECTED`, `TIMEOUT`, `DNS_RESOLUTION_FAILED`, ...). Policy rejections
  are never retryable.
- `fetch_url` declares an `outputSchema`.
- Paging: a new `max_chars` argument (default 20000), plus `totalChars`, `startIndex`
  and `nextStartIndex` in results, and a continuation note in the text.
- A startup warning when HTTP mode binds a non-loopback address.
- Graceful shutdown on SIGINT/SIGTERM in HTTP mode.
- `safe-web-fetch` companion agent skill (`skills/safe-web-fetch`), attached to
  each GitHub release as a zip.
- Release workflows: npm staged publishing (trusted publisher, provenance, human
  approval on npmjs.com), then a post-approval workflow that publishes to the MCP
  Registry and creates the GitHub release. See `RELEASING.md`.
- CI runs a clean-install smoke test: it packs the tarball, installs it in an empty
  directory, and drives the binary over stdio.

### Security

- Block Alibaba Cloud metadata (`100.100.100.200`), which was fetchable under the
  default config, and make AWS IPv6 IMDS (`fd00:ec2::254`) never bypassable. It
  previously sat in the ULA tier that `SAFE_FETCH_ALLOW_LOCAL=true` unlocks.
- Unwrap NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses and check the
  embedded IPv4, so `64:ff9b::a9fe:a9fe` can no longer reach `169.254.169.254`.
- Block CGNAT, multicast, reserved/broadcast, benchmarking, documentation and other
  IANA special-purpose ranges. IPv6 is public only within global unicast `2000::/3`.
- `SAFE_FETCH_TIMEOUT_MS` is now one total deadline covering DNS, connect, headers
  and body across all redirect hops. It was a per-socket idle timer, which a
  slow-drip server could hold open indefinitely.
- The `max_bytes` tool argument can only lower `SAFE_FETCH_MAX_BYTES`, not raise it.
- Refusal messages no longer include resolved IP addresses or raw socket errors.
  That detail is written to the stderr audit log only.

### Fixed

- The `Host` header now includes a non-default port.
- Non-text responses (images, PDFs, ...) are refused with `UNSUPPORTED_CONTENT_TYPE`.
  They used to be returned as garbled text.
- Bodies are decoded with the declared `charset` instead of always as UTF-8.
- `+json` / `+xml` types (RSS, Atom, JSON-LD, ...) are treated as text.
- The server reports its real version instead of a hard-coded `0.1.0`.
- The audit log redacts query-string values and fragments.

### Changed

- **Node 22+ is now required** (Node 20 is end-of-life).
- **Invalid environment variables now stop startup** with a message naming the
  variable, instead of silently falling back to defaults.
  `SAFE_FETCH_ALLOW_LOCAL` accepts `true`/`false`/`1`/`0`.
- **`fetch_url` returns at most 20000 characters per call by default.** Use
  `max_chars` / `start_index` to read more. `start_index` is now documented as a
  character offset, which is how it always behaved.
- Refusal message wording changed (see Security). Anything matching on the old
  text needs updating.

## [0.1.3] - 2026-08-11

### Fixed

- `mcpName` / `server.json` `name`: corrected the GitHub-namespace casing to
  `io.github.Sanoy24/safe-fetch` — the MCP Registry requires an exact
  case-sensitive match to the authenticated GitHub username, and `sanoy24`
  (lowercase) was rejected with a 403.

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

[Unreleased]: https://github.com/Sanoy24/safe-fetch-mcp-server/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Sanoy24/safe-fetch-mcp-server/releases/tag/v0.2.0
[0.1.3]: https://github.com/Sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.3
[0.1.2]: https://github.com/Sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.2
[0.1.1]: https://github.com/Sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.1
[0.1.0]: https://github.com/Sanoy24/safe-fetch-mcp-server/releases/tag/v0.1.0
