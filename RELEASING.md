# Releasing

Releases are published by `.github/workflows/release.yml` when a `vX.Y.Z` tag is pushed.
It publishes to npm (with provenance) and to the MCP Registry, and creates a GitHub
release with the companion skill zip attached.

## One-time setup

1. **npm trusted publisher.** On npmjs.com: package `safe-fetch-mcp-server` → Settings →
   Trusted publishing → add GitHub Actions with:
   - Organization or user: `Sanoy24`
   - Repository: `safe-fetch-mcp-server`
   - Workflow filename: `release.yml`
   - Environment: `release`

   No npm token is stored in GitHub. Publishing authenticates with short-lived OIDC
   credentials.

2. **Approval gate (recommended).** GitHub → Settings → Environments → `release` → add
   yourself as a required reviewer. Every publish then waits for your click.
3. **MCP Registry.** Nothing to configure. The workflow logs in with GitHub OIDC, which
   authorizes the `io.github.Sanoy24/*` namespace.

## Cutting a release

1. Move the `## [Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`,
   and add the link reference at the bottom.
2. Set `X.Y.Z` in `package.json` (`npm version X.Y.Z --no-git-tag-version`) and in both
   `version` fields of `server.json`.
3. Run `npm run release:check && npm run check && npm run smoke`.
4. Merge that PR, then tag the merge commit on `main`:

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

5. Approve the `release` environment when GitHub asks.

The workflow re-runs every check and refuses to publish if the tag, `package.json`,
`server.json` and `CHANGELOG.md` disagree.

## Versioning

[Semantic Versioning](https://semver.org/). While on `0.x`, breaking changes bump the
minor version. Breaking changes include changes to refusal behaviour, error codes,
result fields, defaults, config parsing and the supported Node range.
