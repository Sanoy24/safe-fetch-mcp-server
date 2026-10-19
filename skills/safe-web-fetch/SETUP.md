# Setting up safe-fetch for this skill

This skill needs the **safe-fetch** MCP server running locally in your agent. The server
is free and open source (MIT): <https://github.com/Sanoy24/safe-fetch-mcp-server>. It
needs Node.js 22 or newer.

## 1. Add the server to your MCP client

Copy `mcp-config.example.json` into your client's MCP configuration:

```json
{
  "mcpServers": {
    "safe-fetch": {
      "command": "npx",
      "args": ["-y", "safe-fetch-mcp-server"]
    }
  }
}
```

Where that goes:

| Client         | Location                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------- |
| Claude Code    | `claude mcp add safe-fetch -- npx -y safe-fetch-mcp-server`, or `.mcp.json` in your project |
| Claude Desktop | Settings → Developer → Edit Config (`claude_desktop_config.json`)                           |
| Codex          | `codex mcp add safe-fetch -- npx -y safe-fetch-mcp-server`, or `~/.codex/config.toml`       |
| Other clients  | The client's MCP server config. Use the same `command` and `args`                           |

Restart the client. A `fetch_url` tool should appear.

Exact steps for Claude Code, Claude Desktop, Codex, VS Code, Cursor and Windsurf are in the
[README install section](https://github.com/Sanoy24/safe-fetch-mcp-server#install).

## 2. Install the skill

Put this folder (`SKILL.md` and its files) where your agent loads skills. For Claude
Code, that's `~/.claude/skills/safe-web-fetch/` (personal) or
`.claude/skills/safe-web-fetch/` (one project).

## 3. Optional settings

The defaults are safe. Override them with an `env` block next to `command`:

```json
"env": { "SAFE_FETCH_ALLOWLIST": "docs.python.org,developer.mozilla.org" }
```

| Variable                   | Default   | Effect                                                                                                            |
| -------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------- |
| `SAFE_FETCH_ALLOWLIST`     | _(empty)_ | Comma-separated host allowlist. When set, only these hosts are allowed                                            |
| `SAFE_FETCH_MAX_BYTES`     | `5000000` | Download cap per fetch                                                                                            |
| `SAFE_FETCH_TIMEOUT_MS`    | `10000`   | Total time limit per fetch, including redirects                                                                   |
| `SAFE_FETCH_MAX_REDIRECTS` | `5`       | Redirect limit (0–20)                                                                                             |
| `SAFE_FETCH_ALLOW_LOCAL`   | `false`   | Allows loopback and private networks. **Trusted local development only.** Cloud metadata stays blocked regardless |
| `SAFE_FETCH_HTTPS_ONLY`    | `false`   | Refuse plain `http://`                                                                                            |
| `SAFE_FETCH_ALLOWED_PORTS` | _(any)_   | Restrict destination ports, e.g. `443`                                                                            |
| `SAFE_FETCH_CACHE_TTL_MS`  | `0` (off) | Reuse responses for this long (still re-checked against policy on every use)                                      |

An invalid value stops the server with a message naming the variable. Check your
client's MCP logs if `fetch_url` doesn't appear.

## Troubleshooting

- **No `fetch_url` tool:** run `npx -y safe-fetch-mcp-server` in a terminal. It should print
  `safe-fetch-mcp-server running on stdio` to stderr and then wait. Stop it with Ctrl+C.
  If it errors, check `node --version` (22+ is required).
- **"Refused: … private or non-public address":** working as intended. The URL points at
  your local machine or network.
- **Security issues:** report them privately at
  <https://github.com/Sanoy24/safe-fetch-mcp-server/security/advisories/new>.
