// SPDX-License-Identifier: MIT

package app

import (
	"fmt"

	"github.com/skaphos/wake-forensics-mcp/internal/config"
	"github.com/skaphos/wake-forensics-mcp/internal/service"
)

func Run(args []string) error {
	cfg := config.Default()
	svc := service.New(cfg)
	if err := svc.Validate(); err != nil {
		return err
	}
	if len(args) > 0 && args[0] != "serve" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}
