# Security policy

`safe-fetch-mcp-server` exists to make outbound fetches safe for AI agents, so security
reports are the most valuable contribution you can make.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
[**Report a vulnerability**](https://github.com/Sanoy24/safe-fetch-mcp-server/security/advisories/new).

Please include:

- the `fetch_url` arguments, or the HTTP request for HTTP mode
- the relevant `SAFE_FETCH_*` settings
- the package version you ran
- what happened versus what the [threat model](docs/threat-model.md) says should happen

Use local fixtures, or hosts you control, to demonstrate. Never use third-party internal
systems.

What to expect:

| Step                            | Target                                                            |
| ------------------------------- | ----------------------------------------------------------------- |
| Acknowledgement                 | within 3 days                                                     |
| Initial assessment              | within 7 days                                                     |
| Fix for confirmed High/Critical | released as soon as a tested fix is ready, usually within 30 days |

Confirmed issues get a GitHub Security Advisory and a regression test. Reporters are
credited unless they prefer otherwise.

## In scope

Anything that lets a `fetch_url` call reach a destination the [threat model](docs/threat-model.md)
says is refused, or exceed its limits. Examples: SSRF or guard bypasses (encodings, DNS
rebinding, redirects, IPv6 forms), deadline or byte-cap bypasses, leaks of internal
addresses to the caller, and HTTP-mode Host/Origin bypasses.

## Out of scope

Things the threat model lists under
[Not guaranteed](docs/threat-model.md#not-guaranteed): prompt injection in fetched
content, missing authentication in HTTP mode, and reachability of public hosts or ports.
Also out of scope: findings that require operator-controlled settings such as
`SAFE_FETCH_ALLOW_LOCAL=true` reaching private addresses, which is the intended behaviour.

## Supported versions

| Version              | Supported                        |
| -------------------- | -------------------------------- |
| Latest minor release | ✅                               |
| Older releases       | ❌ Upgrade to the latest release |

## More

- [Threat model](docs/threat-model.md): matrix, address classes, trust boundaries
- [Security evidence](docs/security-evidence.md): OWASP MCP Top 10 mapping, scanner results
