// SPDX-License-Identifier: MIT

package app

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/skaphos/wake-audit-mcp/internal/config"
	"github.com/skaphos/wake-audit-mcp/internal/mcpserver"
)

// serve runs the audit MCP server over stdio, exposing the audit_repository
// and audit_org tools. Stdout is owned by the MCP protocol; diagnostics must
// go to stderr.
//
// Credentials for remote and org-wide scans are resolved from the environment
// (WAKE_GITHUB_TOKEN / GITHUB_TOKEN / GH_TOKEN, and WAKE_GITHUB_BASE_URL for
// GitHub Enterprise). Local-path audits need no credentials.
func serve(ctx context.Context) error {
	server, err := mcpserver.New(config.FromEnv())
	if err != nil {
		return err
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}
