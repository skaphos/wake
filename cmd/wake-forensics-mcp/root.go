// SPDX-License-Identifier: MIT

package wakeforensicsmcp

import (
	"fmt"
	"os"

	"github.com/skaphos/wake-forensics-mcp/internal/app"
)

func Execute() {
	if err := app.Run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
