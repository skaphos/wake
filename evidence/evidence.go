// SPDX-License-Identifier: MIT

package evidence

import "time"

type RepositoryTarget struct {
	Repository   string   `json:"repository"`
	Subpaths     []string `json:"subpaths,omitempty"`
	RevisionFrom string   `json:"revision_from,omitempty"`
	RevisionTo   string   `json:"revision_to,omitempty"`
}

type ContributorIdentity struct {
	CanonicalName  string   `json:"canonical_name"`
	CanonicalEmail string   `json:"canonical_email,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	Ambiguous      bool     `json:"ambiguous,omitempty"`
}

type CommitRecord struct {
	SHA         string              `json:"sha"`
	Author      ContributorIdentity `json:"author"`
	AuthoredAt  time.Time           `json:"authored_at"`
	Summary     string              `json:"summary"`
	TouchedPath []PathDelta         `json:"touched_paths,omitempty"`
	Artifacts   map[string]Artifact `json:"artifacts,omitempty"`
}

type PathDelta struct {
	Path      string `json:"path"`
	Change    string `json:"change"`
	Additions int    `json:"additions,omitempty"`
	Deletions int    `json:"deletions,omitempty"`
}

type Artifact struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Bundle struct {
	Target  RepositoryTarget `json:"target"`
	Commits []CommitRecord   `json:"commits"`
}
