// SPDX-License-Identifier: MIT

package wakeeventsmcp

import (
	"fmt"
	"os"

	"github.com/skaphos/wake-events-mcp/internal/app"
)

func Execute() {
	if err := app.Run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
