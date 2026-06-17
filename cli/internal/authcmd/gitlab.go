// SPDX-License-Identifier: MIT

package authcmd

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/cli/go-gh/v2/pkg/browser"
	"github.com/cli/oauth/device"
	credentials "github.com/skaphos/wake-forensics-mcp/auth/credentials"
)

// Shared Skaphos OAuth App client ID for gitlab.com (non-confidential public
// app; no secret required). Override with --client-id or WAKE_GITLAB_CLIENT_ID
// for self-hosted instances.
const defaultGitLabClientID = "c9766f569e9be5ee467fe3c50d5c8e44baec72e86132e4e1d7b761827bc448f0"

func runGitLab(ctx context.Context, args []string, stdin io.Reader, out, errw io.Writer) error {
	fs := flag.NewFlagSet("auth gitlab", flag.ContinueOnError)
	fs.SetOutput(errw)
	var (
		hostname     string
		withToken    bool
		clientID     string
		clientSecret string
		copyCode     bool
		web          bool
		insecure     bool
	)
	fs.StringVar(&hostname, "hostname", "", "GitLab hostname (default: gitlab.com)")
	fs.BoolVar(&withToken, "with-token", false, "read a Personal Access Token from standard input")
	fs.StringVar(&clientID, "client-id", "", "OAuth application Client ID (required for self-hosted device flow)")
	fs.StringVar(&clientSecret, "client-secret", "", "OAuth application Client Secret (only for confidential apps)")
	fs.BoolVar(&copyCode, "clipboard", false, "copy the user code to the clipboard")
	fs.BoolVar(&web, "web", false, "open the verification URL in your browser automatically")
	fs.BoolVar(&insecure, "insecure-storage", false, "save to plaintext hosts.yml instead of the system keyring")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if hostname == "" {
		hostname = "gitlab.com"
	}
	provider := credentials.ProviderGitLab

	if withToken {
		token, err := readToken(stdin)
		if err != nil {
			return err
		}
		store, err := storeForStorage(insecure)
		if err != nil {
			return fmt.Errorf("initialize credential store: %w", err)
		}
		usedInsecure, err := store.Save(ctx, provider, hostname, credentials.Token{
			Type:        credentials.TokenTypePAT,
			AccessToken: token,
		}, false)
		if err != nil {
			return fmt.Errorf("store GitLab token: %w", err)
		}
		reportSaved(out, usedInsecure, "", hostname)
		return nil
	}

	if clientID == "" {
		clientID = os.Getenv("WAKE_GITLAB_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("WAKE_GITLAB_CLIENT_SECRET")
	}
	isSelfHosted := hostname != "gitlab.com"
	usingPublicApp := clientID == ""
	if isSelfHosted && usingPublicApp {
		return fmt.Errorf(`Self-hosted GitLab detected (%s) — built-in Skaphos credentials only work against gitlab.com.

Register an OAuth Application on your instance and provide its Client ID:

  wake auth gitlab --hostname %s --client-id YOUR_CLIENT_ID

Enable "Device authorization grant flow" with scope read_api. A --client-secret is only needed for confidential apps.`, hostname, hostname)
	}
	if clientID == "" {
		clientID = defaultGitLabClientID
	}

	baseURL := "https://" + hostname
	httpClient := &http.Client{Timeout: 15 * time.Second}
	fmt.Fprintf(out, "Requesting device code for %s...\n", hostname)
	code, err := device.RequestCode(httpClient, baseURL+"/oauth/authorize_device", clientID, []string{"read_api"})
	if err != nil {
		if err == device.ErrUnsupported {
			return fmt.Errorf("this GitLab instance does not support device flow; use --with-token instead")
		}
		return fmt.Errorf("request device code: %w", err)
	}

	fmt.Fprintf(out, "\nFirst copy your one-time code: %s\n", code.UserCode)
	if copyCode {
		if err := clipboard.WriteAll(code.UserCode); err == nil {
			fmt.Fprintln(out, "  (copied to clipboard)")
		}
	}
	if web {
		b := browser.New("", out, errw)
		if err := b.Browse(code.VerificationURI); err != nil {
			fmt.Fprintf(errw, "Failed to open browser: %v\n", err)
			fmt.Fprintf(out, "Please open this URL manually: %s\n", code.VerificationURI)
		}
	} else {
		fmt.Fprintf(out, "Then visit: %s\n\n", code.VerificationURI)
	}

	fmt.Fprintln(out, "Waiting for authorization...")
	tok, err := device.Wait(ctx, httpClient, baseURL+"/oauth/token", device.WaitOptions{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		DeviceCode:   code,
	})
	if err != nil {
		if err == device.ErrTimeout {
			return fmt.Errorf("device authorization timed out")
		}
		return fmt.Errorf("authentication failed: %w", err)
	}

	username := fetchGitLabUsername(baseURL, tok.Token)
	store, err := storeForStorage(insecure)
	if err != nil {
		return fmt.Errorf("initialize credential store: %w", err)
	}
	usedInsecure, err := store.Save(ctx, provider, hostname, credentials.Token{
		Type:        credentials.TokenTypeOAuth,
		AccessToken: tok.Token,
		Username:    username,
	}, false)
	if err != nil {
		return fmt.Errorf("store GitLab token: %w", err)
	}
	reportSaved(out, usedInsecure, username, hostname)
	return nil
}

func readToken(stdin io.Reader) (string, error) {
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			return line, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	return "", fmt.Errorf("no token provided on stdin")
}

// fetchGitLabUsername is a best-effort username lookup for status display.
func fetchGitLabUsername(baseURL, accessToken string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", baseURL+"/api/v4/user", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var u struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return ""
	}
	return u.Username
}
