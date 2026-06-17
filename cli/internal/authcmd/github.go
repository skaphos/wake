// SPDX-License-Identifier: MIT

package authcmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/browser"
	"github.com/cli/oauth"
	oauthapi "github.com/cli/oauth/api"
	credentials "github.com/skaphos/wake-forensics-mcp/auth/credentials"
)

// Shared Skaphos OAuth App credentials for github.com (safe to embed for a
// public CLI client). Override with --client-id/--client-secret or
// WAKE_GITHUB_CLIENT_ID / WAKE_GITHUB_CLIENT_SECRET (required for GHES, or to
// point at a dedicated Wake OAuth App once one is registered).
const (
	defaultGitHubClientID     = "Ov23liDHsFVqZE2z7r16"
	defaultGitHubClientSecret = "6b0e3062797258cdc9fcc80ce5b7774be2d4d0a2"
)

func runGitHub(ctx context.Context, args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("auth github", flag.ContinueOnError)
	fs.SetOutput(errw)
	var (
		hostname     string
		web          bool
		insecure     bool
		copyCode     bool
		clientID     string
		clientSecret string
	)
	fs.StringVar(&hostname, "hostname", "", "GitHub hostname (default: github.com)")
	fs.BoolVar(&web, "web", false, "use the browser-based flow instead of the device flow")
	fs.BoolVar(&insecure, "insecure-storage", false, "save to plaintext hosts.yml instead of the system keyring")
	fs.BoolVar(&copyCode, "clipboard", false, "copy the one-time code to the clipboard (device flow)")
	fs.StringVar(&clientID, "client-id", "", "OAuth client ID (required for GitHub Enterprise Server)")
	fs.StringVar(&clientSecret, "client-secret", "", "OAuth client secret (required for GitHub Enterprise Server)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if hostname == "" {
		hostname = "github.com"
	}
	if clientID == "" {
		clientID = os.Getenv("WAKE_GITHUB_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("WAKE_GITHUB_CLIENT_SECRET")
	}

	isEnterprise := hostname != "github.com" && !strings.HasSuffix(hostname, ".github.com")
	usingDefaultCreds := clientID == "" && clientSecret == ""
	if isEnterprise && usingDefaultCreds {
		return fmt.Errorf(`GitHub Enterprise Server detected (%s) — built-in Skaphos credentials only work against github.com.

Register an OAuth App on your GHES instance and provide its credentials:

  wake auth github --hostname %s --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET

Enable Device Flow and use callback http://127.0.0.1/callback.`, hostname, hostname)
	}
	if clientID == "" {
		clientID = defaultGitHubClientID
	}
	if clientSecret == "" {
		clientSecret = defaultGitHubClientSecret
	}

	host, err := oauth.NewGitHubHost("https://" + hostname)
	if err != nil {
		return fmt.Errorf("invalid GitHub host: %w", err)
	}
	flow := &oauth.Flow{
		Host:         host,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CallbackURI:  "http://127.0.0.1/callback",
		Scopes:       []string{"repo", "read:org", "gist"},
	}
	flow.DisplayCode = func(code, verificationURL string) error {
		fmt.Fprintf(out, "First copy your one-time code: %s\n", code)
		if copyCode {
			if err := clipboard.WriteAll(code); err == nil {
				fmt.Fprintln(out, "  (copied to clipboard)")
			}
		}
		fmt.Fprintf(out, "Open %s in your browser to authorize.\n", verificationURL)
		return nil
	}
	flow.BrowseURL = func(url string) error {
		b := browser.New("", out, errw)
		if err := b.Browse(url); err != nil {
			fmt.Fprintf(errw, "Failed to open browser: %v\n", err)
			fmt.Fprintf(out, "Please open this URL manually: %s\n", url)
		}
		return nil
	}

	fmt.Fprintln(out, "Authenticating with GitHub...")
	var token *oauthapi.AccessToken
	if web {
		token, err = flow.WebAppFlow()
	} else {
		token, err = flow.DetectFlow()
	}
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	username := ""
	if client, err := api.NewGraphQLClient(api.ClientOptions{AuthToken: token.Token, Host: hostname}); err == nil {
		var query struct {
			Viewer struct{ Login string }
		}
		if err := client.Query("UserCurrent", &query, nil); err == nil {
			username = query.Viewer.Login
		}
	}

	store, err := storeForStorage(insecure)
	if err != nil {
		return fmt.Errorf("initialize credential store: %w", err)
	}
	usedInsecure, err := store.Save(ctx, credentials.ProviderGitHub, hostname, credentials.Token{
		Type:        credentials.TokenTypeOAuth,
		AccessToken: token.Token,
		Username:    username,
	}, false)
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	reportSaved(out, usedInsecure, username, hostname)
	return nil
}

func reportSaved(out io.Writer, usedInsecure bool, username, hostname string) {
	fmt.Fprintln(out)
	if usedInsecure {
		fmt.Fprintln(out, "✓ Authentication complete. Token saved to plaintext hosts.yml (insecure).")
	} else {
		fmt.Fprintln(out, "✓ Authentication complete. Token saved to system keyring.")
	}
	if username != "" {
		fmt.Fprintf(out, "  Logged in as %s on %s\n", username, hostname)
	} else {
		fmt.Fprintf(out, "  Logged into %s\n", hostname)
	}
	fmt.Fprintln(out, "\nRun `wake auth status` to verify.")
}
