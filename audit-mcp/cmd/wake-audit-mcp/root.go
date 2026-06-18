// SPDX-License-Identifier: MIT

// Package wakeauditmcp is the console entry point for the audit MCP server.
package wakeauditmcp

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/skaphos/wake-audit-mcp/internal/app"
)

// Execute runs the audit MCP command, exiting non-zero on error.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := app.Run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
