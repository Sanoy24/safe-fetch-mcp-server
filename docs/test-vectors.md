# SSRF test vectors

Every input below must be **refused with `POLICY_REJECTED`** by `fetch_url`. Each one
reproduces a bypass class that has broken real fetch servers. The list is enforced by
[`test/vectors.spec.ts`](../test/vectors.spec.ts): CI fails if a vector stops being refused,
or if this page and the tests drift apart.

The tests are hermetic. A fake resolver answers every DNS lookup (including wildcard-DNS
names), and redirect vectors use a local fixture. To check another fetch server, run these
inputs against **your own** infrastructure only. Never probe systems you don't control.

Why they're refused, in one line: the URL is parsed with the WHATWG parser, the scheme and
userinfo are checked, the hostname is resolved, and **every resolved IP** is classified
before connecting. The connection is then pinned to that IP, and every redirect hop
repeats all of it. See the [threat model](threat-model.md).

## Direct requests

| ID  | Input                                      | Class                                            | Seen in                                                                               |
| --- | ------------------------------------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| V01 | `http://169.254.169.254/latest/meta-data/` | Cloud metadata (AWS, GCP, Azure, OCI)            | [mcp-server-fetch #4143](https://github.com/modelcontextprotocol/servers/issues/4143) |
| V02 | `http://100.100.100.200/latest/meta-data/` | Alibaba Cloud metadata                           |                                                                                       |
| V03 | `http://[fd00:ec2::254]/latest/meta-data/` | AWS IMDS over IPv6                               |                                                                                       |
| V04 | `http://metadata.google.internal/…`        | Metadata via a hostname                          |                                                                                       |
| V05 | `http://[::ffff:127.0.0.1]/`               | IPv4-mapped IPv6                                 | CVE-2026-49857                                                                        |
| V06 | `http://[::ffff:7f00:1]/`                  | IPv4-mapped IPv6, hex form                       |                                                                                       |
| V07 | `http://[0:0:0:0:0:ffff:169.254.169.254]/` | IPv4-mapped metadata, expanded                   |                                                                                       |
| V08 | `http://[::127.0.0.1]/`                    | IPv4-compatible IPv6 (deprecated)                |                                                                                       |
| V09 | `http://[64:ff9b::a9fe:a9fe]/`             | NAT64 prefix embedding metadata                  |                                                                                       |
| V10 | `http://[2002:a9fe:a9fe::]/`               | 6to4 prefix embedding metadata                   |                                                                                       |
| V11 | `http://[::1]/`                            | Bracketed IPv6 loopback                          | CVE-2026-80347                                                                        |
| V12 | `http://[::]/`                             | IPv6 unspecified address                         |                                                                                       |
| V13 | `http://[fe80::1]/`                        | IPv6 link-local                                  |                                                                                       |
| V14 | `http://[fc00::1]/`                        | IPv6 unique-local (ULA)                          |                                                                                       |
| V15 | `http://2130706433/`                       | Decimal IPv4                                     |                                                                                       |
| V16 | `http://0x7f000001/`                       | Hex IPv4                                         |                                                                                       |
| V17 | `http://0177.0.0.1/`                       | Octal octet                                      |                                                                                       |
| V18 | `http://017700000001/`                     | Octal dword                                      |                                                                                       |
| V19 | `http://0x7f.1/`                           | Mixed hex, short form                            |                                                                                       |
| V20 | `http://127.1/`                            | Short-form IPv4                                  |                                                                                       |
| V21 | `http://0/`                                | `0.0.0.0` shorthand (reaches localhost on Linux) |                                                                                       |
| V22 | `http://%31%32%37.0.0.1/`                  | Percent-encoded host                             |                                                                                       |
| V23 | `http://①②⑦.⓪.⓪.①/`                        | Unicode enclosed digits → `127.0.0.1`            |                                                                                       |
| V24 | `http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/`                  | Unicode enclosed digits → metadata               |                                                                                       |
| V25 | `http://localhost/`                        | Loopback hostname                                |                                                                                       |
| V26 | `http://localhost./`                       | Trailing-dot hostname                            |                                                                                       |
| V27 | `http://ＬＯＣＡＬＨＯＳＴ/`               | Full-width hostname                              |                                                                                       |
| V28 | `http://127.0.0.1.nip.io/`                 | Wildcard DNS → loopback                          |                                                                                       |
| V29 | `http://169.254.169.254.sslip.io/`         | Wildcard DNS → metadata                          |                                                                                       |
| V30 | `http://10.0.0.5.nip.io/`                  | Wildcard DNS → private network                   |                                                                                       |
| V31 | `http://10.0.0.1/`                         | RFC 1918                                         |                                                                                       |
| V32 | `http://172.16.0.1/`                       | RFC 1918                                         |                                                                                       |
| V33 | `http://192.168.0.1/`                      | RFC 1918                                         |                                                                                       |
| V34 | `http://100.64.0.1/`                       | CGNAT / shared address space                     |                                                                                       |
| V35 | `http://224.0.0.1/`                        | Multicast                                        |                                                                                       |
| V36 | `http://255.255.255.255/`                  | Broadcast                                        |                                                                                       |
| V37 | `http://example.com@127.0.0.1/`            | Userinfo makes the real host look external       |                                                                                       |
| V38 | `http://127.0.0.1\@example.com/`           | Backslash parser confusion                       |                                                                                       |
| V39 | `http://user:pass@example.com/`            | Embedded credentials                             |                                                                                       |
| V40 | `file:///etc/passwd`                       | Local file scheme                                | [mcp-server-fetch #4205](https://github.com/modelcontextprotocol/servers/issues/4205) |
| V41 | `gopher://127.0.0.1:6379/_INFO`            | Gopher (protocol smuggling into Redis etc.)      |                                                                                       |
| V42 | `dict://127.0.0.1:11211/stats`             | DICT scheme                                      |                                                                                       |
| V43 | `ftp://example.com/`                       | FTP                                              |                                                                                       |
| V44 | `data:text/plain,hello`                    | `data:` URL                                      |                                                                                       |
| V45 | `javascript:alert(1)`                      | `javascript:` URL                                |                                                                                       |

### Never allowed, even with `SAFE_FETCH_ALLOW_LOCAL=true`

Opting into local access unlocks loopback and private ranges for a trusted dev setup. It never unlocks cloud metadata, link-local, multicast or broadcast. These vectors are re-run with `allowLocal` on and must still be refused:

**V01, V02, V03, V04, V07, V09, V10, V13, V24, V29, V35, V36.**

## Redirect targets

A fetch to an allowed page that answers `302 Location: <target>`. Every hop is re-checked
from scratch, so these are refused exactly as if requested directly.

| ID  | Redirect target                            | Class                               | Seen in                                                                               |
| --- | ------------------------------------------ | ----------------------------------- | ------------------------------------------------------------------------------------- |
| R01 | `http://169.254.169.254/latest/meta-data/` | Redirect to metadata                | [mcp-server-fetch #4116](https://github.com/modelcontextprotocol/servers/issues/4116) |
| R02 | `//169.254.169.254/latest/meta-data/`      | Scheme-relative redirect            |                                                                                       |
| R03 | `http://[::ffff:169.254.169.254]/`         | Redirect to IPv4-mapped metadata    |                                                                                       |
| R04 | `http://100.100.100.200/`                  | Redirect to Alibaba metadata        |                                                                                       |
| R05 | `file:///etc/passwd`                       | Redirect to a local file            |                                                                                       |
| R06 | `http://169.254.169.254.nip.io/`           | Redirect to wildcard DNS → metadata |                                                                                       |

## Covered by other suites

These classes need timing or a stateful resolver, so they live in dedicated specs:

| Class                                                                    | Spec                                                          |
| ------------------------------------------------------------------------ | ------------------------------------------------------------- |
| DNS rebinding: the first lookup is public, later ones internal (pinning) | [`test/pinning.spec.ts`](../test/pinning.spec.ts)             |
| Mixed DNS answers (one public plus one private A record)                 | [`test/pinning.spec.ts`](../test/pinning.spec.ts)             |
| Slow-drip bodies, hung DNS, redirect chains that run out the clock       | [`test/deadline.spec.ts`](../test/deadline.spec.ts)           |
| HTTPS → HTTP redirect downgrade                                          | [`test/policyOptions.spec.ts`](../test/policyOptions.spec.ts) |
| A cache hit replaying content after policy or DNS changed                | [`test/cache.spec.ts`](../test/cache.spec.ts)                 |

Know a bypass class that isn't here? Please report it privately
(see [SECURITY.md](../SECURITY.md)) and it'll be added with a regression test.
