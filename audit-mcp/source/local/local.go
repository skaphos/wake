// SPDX-License-Identifier: MIT

// Package local provides an audit.FileTree backed by a local checkout: a
// filesystem walk with sane ignores and a per-file size cap for content
// reads. It is the no-network path used to validate the audit engine and
// the explicit opt-in single-repository audit mode.
package local

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skaphos/wake-core/audit"
)

// DefaultMaxFileSize caps how many bytes ReadFile returns per file; content
// beyond it is truncated, which is acceptable for evidence scanning.
const DefaultMaxFileSize = 1 << 20 // 1 MiB

// ignoredDirs are skipped wholesale during the walk.
var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".terraform": true, ".idea": true, ".vscode": true,
}

// Tree is a read-only local file tree.
type Tree struct {
	root        string
	info        audit.RepoInfo
	paths       []string
	maxFileSize int64
}

// New walks root and returns a Tree. The repository name defaults to the
// base name of root.
func New(root string) (*Tree, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	t := &Tree{root: abs, info: audit.RepoInfo{Name: filepath.Base(abs)}, maxFileSize: DefaultMaxFileSize}

	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != abs && ignoredDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		t.paths = append(t.paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(t.paths)
	return t, nil
}

// WithRepoInfo overrides the repository metadata (name, archived, fork).
func (t *Tree) WithRepoInfo(info audit.RepoInfo) *Tree {
	t.info = info
	return t
}

// Paths implements audit.FileTree.
func (t *Tree) Paths() []string { return t.paths }

// Repo implements audit.FileTree.
func (t *Tree) Repo() audit.RepoInfo { return t.info }

// ReadFile implements audit.FileTree, returning up to maxFileSize bytes of
// the file at the repo-relative path. Paths are constrained to the tree
// root.
func (t *Tree) ReadFile(p string) ([]byte, error) {
	clean := filepath.Clean(filepath.FromSlash(p))
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return nil, fs.ErrNotExist
	}
	full := filepath.Join(t.root, clean)

	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(io.LimitReader(f, t.maxFileSize))
}
