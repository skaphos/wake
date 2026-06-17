// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/skaphos/wake-forensics-mcp/internal/mcpserver"
	"github.com/skaphos/wake-forensics-mcp/source/remote/configload"
)

// serve runs the forensics MCP server over stdio, exposing the get_commits
// tool (remote GitHub/GitLab commit evidence). Stdout is owned by the MCP
// protocol; diagnostics must go to stderr.
//
// Configuration is resolved from the wake config file (~/.config/wake/
// config.yaml and friends) plus the environment. When no token resolves, the
// commit client falls back to the credential store populated by `wake auth`,
// so a logged-in operator needs no environment variables.
func serve(ctx context.Context) error {
	cfg, err := configload.Load(env("WAKE_CONFIG"))
	if err != nil {
		return err
	}
	server, err := mcpserver.New(cfg)
	if err != nil {
		return err
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}

func env(key string) string { return os.Getenv(key) }
