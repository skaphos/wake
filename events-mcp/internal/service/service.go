// SPDX-License-Identifier: MIT

package service

import (
	"fmt"

	"github.com/skaphos/wake-events-mcp/internal/config"
)

type Service struct {
	config config.Config
}

func New(cfg config.Config) Service {
	return Service{config: cfg}
}

func (s Service) Validate() error {
	if s.config.ListenNetwork == "" {
		return fmt.Errorf("listen network must not be empty")
	}
	return nil
}
