// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/skaphos/wake-forensics-mcp/internal/config"
	"github.com/skaphos/wake-forensics-mcp/internal/service"
	"github.com/skaphos/wake-forensics-mcp/target"
)

func Run(ctx context.Context, args []string) error {
	cfg := config.Default()
	svc := service.New(cfg)
	if err := svc.Validate(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "serve" {
		return serve(ctx)
	}
	if args[0] != "resolve" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	if len(args) < 2 {
		return fmt.Errorf("resolve requires a repository path argument")
	}

	resolved, err := svc.ResolveTarget(target.Input{Repository: args[1], Subpaths: args[2:]})
	if err != nil {
		return err
	}
	opened, err := svc.OpenRepository(resolved)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		RepositoryPath string   `json:"repository_path"`
		GitPath        string   `json:"git_path"`
		Subpaths       []string `json:"subpaths,omitempty"`
		RevisionFrom   string   `json:"revision_from,omitempty"`
		RevisionTo     string   `json:"revision_to,omitempty"`
	}{
		RepositoryPath: resolved.RepositoryPath,
		GitPath:        opened.GitPath,
		Subpaths:       resolved.Subpaths,
		RevisionFrom:   resolved.RevisionFrom,
		RevisionTo:     resolved.RevisionTo,
	})
}
