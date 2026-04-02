// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"

	"github.com/skaphos/wake-cli/internal/config"
	"github.com/skaphos/wake-cli/internal/render"
)

func Run(_ context.Context, args []string) error {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		return err
	}
	r := render.New(cfg.OutputFormat)
	if len(args) > 0 {
		return fmt.Errorf("unknown command %q", args[0])
	}
	_, err := r.Render("wake-cli scaffold is ready")
	return err
}
