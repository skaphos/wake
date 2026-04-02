// SPDX-License-Identifier: MIT

package service

import (
	"fmt"

	"github.com/skaphos/wake-forensics-mcp/internal/config"
	"github.com/skaphos/wake-forensics-mcp/internal/repository"
	"github.com/skaphos/wake-forensics-mcp/internal/target"
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

func (s Service) ResolveTarget(input target.Input) (target.Resolved, error) {
	return target.Resolve(input)
}

func (s Service) OpenRepository(resolved target.Resolved) (repository.Opened, error) {
	return repository.OpenReadOnly(resolved.RepositoryPath)
}
