<!-- SPDX-License-Identifier: MIT -->

# Release Process

Wake uses [Release Please](https://github.com/googleapis/release-please) to
own versioning and the changelog, and [GoReleaser](https://goreleaser.com) to
build and publish the binaries.

## Release flow

1. Commits land on `main` through pull requests, using
   [Conventional Commits](https://www.conventionalcommits.org) (`feat:`,
   `fix:`, …) so Release Please can classify them.
2. `.github/workflows/release-please.yml` keeps a rolling **release PR** open
   on `main`, updating the version bump and `CHANGELOG.md` on every push.
3. A maintainer reviews and merges the release PR.
4. On that merge, Release Please creates the `vX.Y.Z` tag and the GitHub
   release (with notes from the changelog).
5. In the same workflow run, GoReleaser builds the binaries and uploads them
   onto that release (`release.mode: append` in `.goreleaser.yaml`).

There is no separate tag-push workflow — Release Please owns the tag.

## Published artifacts

For each release, GoReleaser publishes one archive per OS/arch
(`wake_X.Y.Z_<os>_<arch>.tar.gz`, `.zip` on Windows) bundling all four
binaries, plus a `checksums.txt`:

- `wake` — the CLI
- `wake-events-mcp` — events MCP server
- `wake-forensics-mcp` — forensics MCP server
- `wake-audit-mcp` — repository policy-audit MCP server

## Versioning

Wake is versioned as a single unit: one `vX.Y.Z` tag covers the whole
workspace (all modules build at that version). Release Please owns
`.release-please-manifest.json`, `release-please-config.json`, and
`CHANGELOG.md` — do not hand-edit generated release entries except to fix
clear mistakes before merging the release PR.

While the version is pre-1.0, `feat:` bumps the minor and `fix:` bumps the
patch (`bump-minor-pre-major`).

## Required credentials

The release workflow mints a GitHub App token for the Skaphos release bot:

| Name | Type | Purpose |
| --- | --- | --- |
| `RELEASE_BOT_CLIENT_ID` | repository or organization **variable** | Client ID for `actions/create-github-app-token`. |
| `RELEASE_BOT_PRIVATE_KEY` | repository or organization **secret** | Private key for the release bot GitHub App. |

The bot needs `contents: write` and `pull-requests: write` so it can open the
release PR, push the tag, create the release, and upload artifacts.

## Local checks before merging the release PR

The release PR should have green CI. For local parity (matches the CI job set):

```bash
go -C tools tool task ci
```

Individual checks: `task fmt`, `task vet`, `task lint`, `task vuln`,
`task test`, `task build` (all via `go -C tools tool task <name>`).
