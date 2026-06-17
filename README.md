# wake

Umbrella repository and primary public entry point for Wake.

This is a multi-module Go monorepo. The previously separate `wake-*` repositories
have been collapsed into subdirectories here, tied together with a `go.work`
workspace so they build and test as a unit while remaining independent modules.

## Layout

| Directory       | Module                                  | Role                              |
|-----------------|-----------------------------------------|-----------------------------------|
| `core/`         | `github.com/skaphos/wake-core`          | Shared library (confidence, events, evidence, inference, report) |
| `cli/`          | `github.com/skaphos/wake-cli`           | `wake` command-line interface     |
| `events-mcp/`   | `github.com/skaphos/wake-events-mcp`    | Event-classification MCP server   |
| `forensics-mcp/`| `github.com/skaphos/wake-forensics-mcp` | Forensics / commit-evidence MCP server |

Intra-repo module dependencies are wired both through `go.work` (for the unified
workspace) and via `replace` directives in each `go.mod` (so each module also
builds independently).

## Building

```sh
go build ./...    # from a module directory, or use package patterns from the repo root
go test  ./...
```
