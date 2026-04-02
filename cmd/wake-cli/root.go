// SPDX-License-Identifier: MIT

package wakecli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/skaphos/wake-cli/internal/app"
)

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
