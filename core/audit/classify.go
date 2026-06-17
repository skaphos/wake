// SPDX-License-Identifier: MIT

package audit

import (
	"path"
	"sort"
	"strings"
)

// Classify profiles a repository deterministically from its file tree:
// the set of languages present and a coarse archetype. It reads only path
// names (no file contents), so it is cheap and stable. This is the v1
// classifier (DECISIONS/0004): languages/manifests + archetypes
// docs / gitops / iac / service / library.
func Classify(tree FileTree) Classification {
	langs := map[string]bool{}
	var total, docFiles, codeFiles, iacFiles, gitopsHits int
	hasDockerfile := false
	hasEntrypoint := false

	for _, p := range tree.Paths() {
		total++
		lower := strings.ToLower(p)
		base := path.Base(lower)
		ext := path.Ext(lower)

		if isDocFile(base, ext) {
			docFiles++
		}
		if lang, ok := languageOf(base, ext); ok {
			langs[lang] = true
			switch {
			case isIaCLang(lang):
				iacFiles++
			case isCodeLang(lang):
				codeFiles++
			}
		}
		if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || ext == ".dockerfile" {
			hasDockerfile = true
		}
		if isGitOpsMarker(base) {
			gitopsHits++
		}
		if isEntrypoint(lower, base) {
			hasEntrypoint = true
		}
	}

	cls := Classification{Languages: sortedKeys(langs), Archetype: ArchetypeUnknown}
	cls.Archetype = archetype(total, docFiles, codeFiles, iacFiles, gitopsHits, hasDockerfile, hasEntrypoint)
	return cls
}

// archetype applies a fixed precedence over the tallied signals.
func archetype(total, docFiles, codeFiles, iacFiles, gitopsHits int, hasDockerfile, hasEntrypoint bool) Archetype {
	if total == 0 {
		return ArchetypeUnknown
	}
	// Pure documentation: no code, no infra, no gitops — and some docs.
	if codeFiles == 0 && iacFiles == 0 && gitopsHits == 0 {
		if docFiles > 0 {
			return ArchetypeDocs
		}
		return ArchetypeUnknown
	}
	// Infrastructure-as-code dominates and there is no app code.
	if iacFiles > 0 && codeFiles == 0 {
		return ArchetypeIaC
	}
	// GitOps config (kustomize/helm/argocd/flux) with no app code.
	if gitopsHits > 0 && codeFiles == 0 {
		return ArchetypeGitOps
	}
	// App code present: service if it looks deployable, else library.
	if codeFiles > 0 {
		if hasDockerfile || hasEntrypoint {
			return ArchetypeService
		}
		return ArchetypeLibrary
	}
	return ArchetypeUnknown
}

var docExts = map[string]bool{".md": true, ".mdx": true, ".rst": true, ".txt": true, ".adoc": true}

func isDocFile(base, ext string) bool {
	if docExts[ext] {
		return true
	}
	switch base {
	case "readme", "license", "licence", "notice", "authors", "contributors", "changelog", "contributing":
		return true
	}
	return false
}

// languageOf maps a filename/extension to a language. Manifests win over
// extensions where both could apply.
func languageOf(base, ext string) (string, bool) {
	switch base {
	case "go.mod", "go.sum":
		return "go", true
	case "package.json":
		return "javascript", true
	case "pyproject.toml", "requirements.txt", "pipfile", "setup.py":
		return "python", true
	case "pom.xml", "build.gradle", "build.gradle.kts":
		return "java", true
	case "cargo.toml":
		return "rust", true
	case "gemfile":
		return "ruby", true
	}
	switch ext {
	case ".go":
		return "go", true
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript", true
	case ".ts", ".tsx":
		return "typescript", true
	case ".py":
		return "python", true
	case ".java":
		return "java", true
	case ".kt", ".kts":
		return "kotlin", true
	case ".cs", ".csproj":
		return "csharp", true
	case ".rb":
		return "ruby", true
	case ".rs":
		return "rust", true
	case ".tf", ".hcl":
		return "terraform", true
	case ".bicep":
		return "bicep", true
	}
	return "", false
}

// isCodeLang reports general-purpose application languages (used to decide
// service/library), excluding infra languages.
func isCodeLang(lang string) bool {
	switch lang {
	case "go", "javascript", "typescript", "python", "java", "kotlin", "csharp", "ruby", "rust":
		return true
	}
	return false
}

func isIaCLang(lang string) bool {
	return lang == "terraform" || lang == "bicep"
}

func isGitOpsMarker(base string) bool {
	switch base {
	case "kustomization.yaml", "kustomization.yml", "chart.yaml", "helmfile.yaml", "helmfile.yml":
		return true
	}
	return false
}

// isEntrypoint detects a deployable entrypoint shape (a service marker).
func isEntrypoint(lowerPath, base string) bool {
	if base == "main.go" {
		// root or under cmd/ is a service entrypoint; deep elsewhere counts too.
		return true
	}
	switch base {
	case "main.py", "__main__.py", "index.js", "server.js", "app.py":
		return strings.Contains(lowerPath, "cmd/") || !strings.Contains(strings.TrimSuffix(lowerPath, base), "/")
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
