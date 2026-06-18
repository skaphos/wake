<!-- SPDX-License-Identifier: MIT -->

# wake-audit-mcp

Repository policy-audit services for Wake: `audit.FileTree` sources (local
checkout, remote GitHub) that feed the pure [`core/audit`](../core/audit)
engine, plus an MCP-over-stdio server exposing the audit as agent tools.

## MCP server

`wake-audit-mcp serve` (the default command) runs an MCP server over stdio.

### Tools

| Tool | Purpose |
|------|---------|
| `audit_repository` | Audit one repository — a local `path`, or a remote GitHub `owner`+`repo` — against a rule pack. Returns evidence-backed, confidence-scored findings plus a Markdown summary. |
| `audit_org` | Audit every eligible repository in a GitHub `org` (archived and forked repos excluded by default). Returns a per-repository report array, an org rollup, and a Markdown table. |

Both tools accept an optional `rules_yaml` (a custom rule pack as YAML);
without it the built-in default pack is used. Both are read-only and reach an
external service for remote/org targets.

`audit_org` audits at most `max_repos` repositories (default 300) after
filtering; when more are eligible the result is flagged `truncated`.

### Credentials

Remote and org-wide scans authenticate to GitHub from the environment, using
Wake's standard precedence:

- Token: `WAKE_GITHUB_TOKEN`, then `GITHUB_TOKEN`, then `GH_TOKEN`
- Enterprise API root: `WAKE_GITHUB_BASE_URL` (e.g. `https://ghe.example.com/api/v3/`)

Local-path audits need no credentials. Unauthenticated remote access works for
public repositories at a low rate limit.
