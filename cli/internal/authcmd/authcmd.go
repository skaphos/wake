// SPDX-License-Identifier: MIT

// Package authcmd implements the `wake auth` command tree: logging in to
// GitHub or GitLab (OAuth, recommended) and managing the resulting
// credentials. Credentials are stored by the shared credential store in
// wake-forensics-mcp/auth/credentials (system keyring preferred, plaintext
// hosts.yml fallback), so both the `wake analyze --remote` path and the
// `wake-forensics-mcp` get_commits MCP tool pick them up automatically.
package authcmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	credentials "github.com/skaphos/wake-forensics-mcp/auth/credentials"
)

// Run dispatches a `wake auth <subcommand>` invocation.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage(stdout)
	}
	switch args[0] {
	case "github":
		return runGitHub(ctx, args[1:], stdout, stderr)
	case "gitlab":
		return runGitLab(ctx, args[1:], stdin, stdout, stderr)
	case "status":
		return runStatus(ctx, args[1:], stdout)
	case "logout":
		return runLogout(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		return usage(stdout)
	default:
		return fmt.Errorf("unknown auth subcommand %q (want github|gitlab|status|logout)", args[0])
	}
}

func usage(w io.Writer) error {
	_, err := io.WriteString(w, `wake auth — authenticate with GitHub or GitLab

Usage:
  wake auth github [--hostname H] [--web] [--insecure-storage]
  wake auth gitlab [--hostname H] [--with-token] [--insecure-storage]
  wake auth status [--hostname H]
  wake auth logout [github|gitlab] [--hostname H]

OAuth is recommended and works out of the box for github.com and gitlab.com.
Legacy PATs via WAKE_GITHUB_TOKEN / WAKE_GITLAB_TOKEN continue to work as a fallback.
`)
	return err
}

// storeForStorage returns a credential store honoring --insecure-storage:
// when insecure is true the token is deterministically written to the
// plaintext hosts.yml; otherwise the keyring is preferred with file fallback.
func storeForStorage(insecure bool) (credentials.Store, error) {
	if insecure {
		return credentials.NewInsecure()
	}
	return credentials.New()
}

func runStatus(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("auth status", flag.ContinueOnError)
	fs.SetOutput(out)
	var hostname string
	fs.StringVar(&hostname, "hostname", "", "check status for a specific hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := credentials.New()
	if err != nil {
		return fmt.Errorf("initialize credential store: %w", err)
	}
	refs, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("list credentials: %w", err)
	}
	if hostname != "" {
		filtered := refs[:0:0]
		for _, r := range refs {
			if r.Host == hostname {
				filtered = append(filtered, r)
			}
		}
		refs = filtered
	}

	fmt.Fprintln(out, "Authentication status:")
	fmt.Fprintln(out)

	githubHosts := map[string][]credentials.CredentialRef{}
	var gitlabHosts []credentials.CredentialRef
	for _, ref := range refs {
		if ref.Provider == credentials.ProviderGitHub {
			githubHosts[ref.Host] = append(githubHosts[ref.Host], ref)
		} else {
			gitlabHosts = append(gitlabHosts, ref)
		}
	}

	fmt.Fprintln(out, "GitHub:")
	if len(githubHosts) == 0 {
		fmt.Fprintln(out, "  Not logged in.")
	} else {
		for host, entries := range githubHosts {
			for _, ref := range entries {
				printRef(out, host, ref)
			}
		}
	}
	if hostname == "" && firstNonEmpty(os.Getenv("WAKE_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")) != "" {
		fmt.Fprintln(out, "  • Legacy token available via WAKE_GITHUB_TOKEN / GITHUB_TOKEN (fallback)")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "GitLab:")
	if len(gitlabHosts) == 0 {
		fmt.Fprintln(out, "  Not logged in.")
	} else {
		for _, ref := range gitlabHosts {
			printRef(out, ref.Host, ref)
		}
	}
	if hostname == "" && firstNonEmpty(os.Getenv("WAKE_GITLAB_TOKEN"), os.Getenv("GITLAB_TOKEN")) != "" {
		fmt.Fprintln(out, "  • Legacy token available via WAKE_GITLAB_TOKEN / GITLAB_TOKEN (fallback)")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Run `wake auth github` to authenticate with GitHub using OAuth (recommended).")
	return nil
}

func printRef(out io.Writer, host string, ref credentials.CredentialRef) {
	if ref.Username != "" {
		fmt.Fprintf(out, "  ✓ Logged into %s as %s (source: %s)\n", host, ref.Username, ref.Source)
	} else {
		fmt.Fprintf(out, "  ✓ Logged into %s (source: %s)\n", host, ref.Source)
	}
}

func runLogout(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("auth logout", flag.ContinueOnError)
	fs.SetOutput(out)
	var hostname string
	fs.StringVar(&hostname, "hostname", "", "log out of a specific hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}

	providerArg := ""
	if fs.NArg() > 0 {
		providerArg = strings.ToLower(fs.Arg(0))
	}
	var provider credentials.Provider
	host := "github.com"
	switch providerArg {
	case "", "github":
		provider = credentials.ProviderGitHub
	case "gitlab":
		provider = credentials.ProviderGitLab
		host = "gitlab.com"
	default:
		return fmt.Errorf("unknown provider %q (use github or gitlab)", providerArg)
	}
	if hostname != "" {
		host = hostname
	}

	store, err := credentials.New()
	if err != nil {
		return fmt.Errorf("initialize credential store: %w", err)
	}
	if err := store.Delete(ctx, provider, host); err != nil {
		return fmt.Errorf("remove credentials for %s on %s: %w", provider, host, err)
	}
	fmt.Fprintf(out, "✓ Logged out of %s on %s\n", provider, host)
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
