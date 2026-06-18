// SPDX-License-Identifier: MIT

// Package app is the audit MCP command entry point. The default (and only)
// command is serve, which runs the MCP server over stdio.
package app

import (
	"context"
	"fmt"
)

// Run dispatches the audit-mcp command line. With no arguments, or "serve", it
// starts the MCP server over stdio.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "serve" {
		return serve(ctx)
	}
	return fmt.Errorf("unknown command %q", args[0])
}
