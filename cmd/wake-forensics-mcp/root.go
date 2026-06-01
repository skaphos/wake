// SPDX-License-Identifier: MIT

package wakeforensicsmcp

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/skaphos/wake-forensics-mcp/internal/app"
)

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := app.Run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
