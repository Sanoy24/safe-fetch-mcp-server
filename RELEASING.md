# Releasing

Releases use npm **staged publishing**. CI uploads a version, but it doesn't go live until
a maintainer approves it on npmjs.com with 2FA. A compromised CI run can therefore stage
a version, but never publish one.

| Step                 | Who              | What happens                                                                                                                      |
| -------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Push a `vX.Y.Z` tag  | maintainer       | `release.yml` re-runs every check, then **stages** the version on npm with provenance                                             |
| Approve on npmjs.com | maintainer (2FA) | The version goes live on npm                                                                                                      |
| Run **Post-release** | maintainer       | `post-release.yml` confirms the version is live, publishes to the MCP Registry, and creates the GitHub release with the skill zip |

## One-time setup

1. **npm trusted publisher.** On npmjs.com: package `safe-fetch-mcp-server` → Settings →
   Trusted publishing → GitHub Actions:
   - Organization or user: `Sanoy24`
   - Repository: `safe-fetch-mcp-server`
   - Workflow filename: `release.yml`
   - Environment: `release`
   - Allowed actions: leave **Allow npm publish** and **Allow npm dist-tag** unticked
     (stage-only, as npm recommends).

   No npm token is stored in GitHub. Staging authenticates with short-lived OIDC
   credentials, and those can't approve a staged version.

2. **MCP Registry.** Nothing to configure. The post-release workflow logs in with GitHub
   OIDC, which authorizes the `io.github.Sanoy24/*` namespace.
3. **Optional extra gate:** GitHub → Settings → Environments → `release` → required
   reviewers. npm approval is already a human gate, so this is optional.

## Cutting a release

1. Move the `## [Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`, and
   add the link reference at the bottom.
2. Set `X.Y.Z` in `package.json` (`npm version X.Y.Z --no-git-tag-version`) and in both
   `version` fields of `server.json`.
3. Run `npm run release:check && npm run check && npm run smoke`, then merge the PR.
4. Tag the merge commit on `main`:

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

5. When **Release** finishes, review the staged version on npmjs.com, or run
   `npm stage list` / `npm stage view safe-fetch-mcp-server@X.Y.Z`. Then approve it on the
   website or with `npm stage approve safe-fetch-mcp-server@X.Y.Z`.
6. Run **Post-release**: Actions → Post-release → Run workflow → tag `vX.Y.Z`, or
   `gh workflow run post-release.yml -f tag=vX.Y.Z`.

The workflows refuse to continue if the tag, `package.json`, `server.json` and
`CHANGELOG.md` disagree, or if Post-release runs before the version is live.

## Versioning

[Semantic Versioning](https://semver.org/). While on `0.x`, breaking changes bump the
minor version. Breaking changes include changes to refusal behaviour, error codes,
result fields, defaults, config parsing and the supported Node range.
