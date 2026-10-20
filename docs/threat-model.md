# Threat model

What `safe-fetch-mcp-server` defends against, how, and where each defense is tested.
This is the canonical threat matrix: code comments and tests refer to its row numbers.

## Trust boundaries

| Party                                                                          | Trust                                                                                                           |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **Operator**: whoever sets the `SAFE_FETCH_*` env vars and launches the server | Trusted. Owns the policy.                                                                                       |
| **Caller**: the LLM/agent invoking `fetch_url`                                 | **Untrusted.** It may be steered by prompt-injected content, so tool arguments can never widen operator policy. |
| **Remote servers and DNS**: everything the fetch touches                       | **Hostile.** They control DNS answers, redirects, headers, body size and timing.                                |
| **Fetched content**                                                            | **Untrusted data.** It is labeled as such but not sanitized.                                                    |

The asset being protected is the operator's network position: cloud metadata credentials,
loopback services, and internal hosts reachable from where the server runs.

## Address classes

Every resolved IP is classified once (`classifyIp` in `src/security/ipGuard.ts`):

| Class       | Meaning                                                                         | Allowed?                                           |
| ----------- | ------------------------------------------------------------------------------- | -------------------------------------------------- |
| `forbidden` | Cloud metadata, link-local, multicast, reserved/broadcast                       | **Never**, even with `SAFE_FETCH_ALLOW_LOCAL=true` |
| `private`   | Loopback, RFC-1918, ULA, CGNAT, other IANA special-purpose or non-global ranges | Only with `SAFE_FETCH_ALLOW_LOCAL=true`            |
| `public`    | Everything else for IPv4; only global unicast (`2000::/3`) for IPv6             | Yes                                                |

`forbidden` is checked first, so a metadata `/32` inside a private range
(`100.100.100.200` in `100.64.0.0/10`, `fd00:ec2::254` in `fc00::/7`) stays forbidden.
Unparseable addresses are `forbidden` (fail closed).

## Threat matrix

| #   | Attack                                      | Example                                                                                                  | Defense                                                                                                                                                                                    | Tests                                   |
| --- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| 1   | Cloud metadata SSRF                         | `169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`                                                    | `forbidden` class on the resolved IP                                                                                                                                                       | `ipGuard.spec.ts`, `pinning.spec.ts`    |
| 2   | Private-range SSRF                          | `10.0.0.5`, `192.168.1.1`                                                                                | `private` class on the resolved IP                                                                                                                                                         | `ipGuard.spec.ts`, `ssrf.spec.ts`       |
| 3   | Loopback                                    | `127.0.0.1`, `127.1`, `0.0.0.0`                                                                          | `private` class after normalization                                                                                                                                                        | `ipGuard.spec.ts`, `ssrf.spec.ts`       |
| 4   | IPv4-mapped/compatible IPv6                 | `[::ffff:127.0.0.1]`, `[::127.0.0.1]`                                                                    | Unwrap the embedded IPv4, then classify it                                                                                                                                                 | `ipGuard.spec.ts`, `ssrf.spec.ts`       |
| 5   | IPv6 loopback / ULA / non-global            | `[::1]`, `fc00::/7`, `fec0::/10`                                                                         | Only global unicast IPv6 is public                                                                                                                                                         | `ipGuard.spec.ts`, `ssrf.spec.ts`       |
| 6   | Encoding bypass                             | `2130706433`, `0x7f000001`, `0177.0.0.1`                                                                 | Validate the resolved IP, never the host string                                                                                                                                            | `ssrf.spec.ts`                          |
| 7   | DNS rebinding                               | Resolves public, then private                                                                            | Resolve once, **pin** the socket to that IP via the `lookup` hook                                                                                                                          | `pinning.spec.ts`                       |
| 8   | Redirect-to-internal                        | `302 → http://169.254.169.254/`                                                                          | Full guard re-run on **every** hop; GET only, no headers forwarded                                                                                                                         | `redirects.spec.ts`                     |
| 9   | Non-HTTP schemes                            | `file://`, `gopher://`, `ftp://`                                                                         | Scheme allowlist: `http`, `https`                                                                                                                                                          | `ssrf.spec.ts`, `redirects.spec.ts`     |
| 10  | Credentials in URL                          | `http://user:pass@host`                                                                                  | Userinfo rejected                                                                                                                                                                          | `ssrf.spec.ts`                          |
| 11  | Resource exhaustion                         | Multi-GB body, slow-drip body, hung DNS                                                                  | Byte cap plus **one total deadline** over DNS, connect, headers and body across all hops                                                                                                   | `deadline.spec.ts`, `ssrf.spec.ts`      |
| 12  | IPv4 embedded by NAT64 / 6to4               | `64:ff9b::a9fe:a9fe`, `2002:a9fe:a9fe::`                                                                 | Unwrap the embedded IPv4, then classify it                                                                                                                                                 | `ipGuard.spec.ts`                       |
| 13  | Mixed DNS answers                           | One public A record plus one private A record                                                            | Refuse if **any** answer is not allowed                                                                                                                                                    | `pinning.spec.ts`                       |
| 14  | Caller widens policy                        | `max_bytes: 1e9`                                                                                         | Tool arguments can only tighten operator limits                                                                                                                                            | `fetchUrl.spec.ts`                      |
| 15  | Internal-network oracle via errors          | Probing `jenkins.internal` and reading back its IP                                                       | Refusals name the address class only; IPs and socket errors go to the stderr log                                                                                                           | `fetchUrl.spec.ts`                      |
| 16  | Browser DNS rebinding against HTTP mode     | Malicious page → `127.0.0.1:3000/mcp`                                                                    | Explicit `Host` allowlist; `Origin` refused unless allowlisted; binds `127.0.0.1`                                                                                                          | `httpTransport.spec.ts`                 |
| 17  | Guard bypass by a second fetch path         | A poller re-fetching without the guard                                                                   | One fetch path (`fetchWithRedirects`), re-validated on every call                                                                                                                          | `redirects.spec.ts` (poller regression) |
| 18  | HTTPS → HTTP redirect downgrade             | `https://a/` → `302 http://a/`                                                                           | Refused by default (`SAFE_FETCH_ALLOW_HTTPS_DOWNGRADE` to allow)                                                                                                                           | `policyOptions.spec.ts`                 |
| 19  | Unwanted protocols or ports on public hosts | `http://host:6379/`                                                                                      | Optional `SAFE_FETCH_HTTPS_ONLY` and `SAFE_FETCH_ALLOWED_PORTS`, checked on every hop                                                                                                      | `policyOptions.spec.ts`                 |
| 20  | Cache used to bypass the guard              | Content cached under a looser policy, or a host that now resolves to metadata                            | Every cache hit re-runs URL policy, DNS/IP classification and the downgrade rule on the stored redirect chain; keys include the byte cap                                                   | `cache.spec.ts`                         |
| 21  | Validator leak across redirects             | Sending one origin's ETag to another hop                                                                 | Conditional headers only on the hop that produced them                                                                                                                                     | `cache.spec.ts`                         |
| 22  | Host-pattern confusion                      | `evilexample.com` or `example.com.evil.net` against `*.example.com`; `example.com.`; Unicode look-alikes | Patterns match on label boundaries only; trailing dots ignored; entries normalized to punycode like URL hostnames; deny wins over allow; invalid entries fail startup                      | `hostPatterns.spec.ts`                  |
| 23  | Decompression bomb                          | A few KB of gzip/brotli that expands to gigabytes                                                        | Decompress while streaming; `SAFE_FETCH_MAX_BYTES` counts **decompressed** bytes and reading stops at the cap; only gzip/br/deflate accepted; corrupt data is refused (`INVALID_RESPONSE`) | `compression.spec.ts`                   |

## Not guaranteed

These are outside what the server can enforce. Plan for them separately.

- **Prompt injection.** Fetched content is labeled as untrusted, but labels don't stop a
  model from following injected instructions. The consuming application needs its own
  defenses.
- **Authentication in HTTP mode.** There is none. Origin/Host checks are DNS-rebinding
  protection, not auth. Keep HTTP mode on loopback, or put it behind your own
  authenticating proxy.
- **Content correctness.** The server doesn't verify that a page is accurate, current or benign.
- **Egress beyond IP policy, by default.** Any port on any public host is reachable
  unless you set `SAFE_FETCH_ALLOWLIST`, `SAFE_FETCH_ALLOWED_PORTS` or
  `SAFE_FETCH_HTTPS_ONLY`, or add network-level egress controls.
- **Hostile networks in front of the server.** If your resolver or network path is
  compromised, a "public" IP may route somewhere internal. The guard trusts the routing
  table.

Automated scanners have been run against this repo (see
[`security-evidence.md`](security-evidence.md)). They're keyword-based, so treat their
results as a smoke test, not proof.
