// SPDX-License-Identifier: MIT

package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RepoKeeper enumerates workspace repositories by acting as a client of the
// RepoKeeper MCP server. It spawns the RepoKeeper binary in MCP mode over
// stdio and calls the select_repositories tool.
//
// This requires the RepoKeeper binary to be installed and on PATH (or an
// explicit Command), which is the same precondition as managing the workspace
// at all — see DECISIONS/0002.
type RepoKeeper struct {
	// Command is the RepoKeeper executable. Defaults to "repokeeper".
	Command string
	// Args are the arguments that start its MCP server. Defaults to ["mcp"].
	Args []string
}

const selectRepositoriesTool = "select_repositories"

// Enumerate connects to the RepoKeeper MCP server, calls select_repositories
// with the given query, and returns the matched repositories.
func (rk RepoKeeper) Enumerate(ctx context.Context, q Query) ([]Repo, error) {
	command := rk.Command
	if command == "" {
		command = "repokeeper"
	}
	args := rk.Args
	if args == nil {
		args = []string{"mcp"}
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "wake-cli", Version: version}, nil)
	transport := &mcp.CommandTransport{Command: exec.CommandContext(ctx, command, args...)}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to repokeeper mcp (%q): %w", command, err)
	}
	defer func() { _ = session.Close() }()

	arguments := map[string]any{}
	if q.LabelSelector != "" {
		arguments["label_selector"] = q.LabelSelector
	}
	if q.FieldSelector != "" {
		arguments["field_selector"] = q.FieldSelector
	}
	if q.NameMatch != "" {
		arguments["name_match"] = q.NameMatch
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      selectRepositoriesTool,
		Arguments: arguments,
	})
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", selectRepositoriesTool, err)
	}
	if res.IsError {
		return nil, fmt.Errorf("repokeeper %s failed: %s", selectRepositoriesTool, resultText(res))
	}

	data, err := resultJSON(res)
	if err != nil {
		return nil, err
	}
	return parseSelectResult(data)
}

// version is reported to the MCP server as the client implementation version.
var version = "wake-cli"

// resultJSON extracts the JSON payload from a tool result, preferring the
// structured content and falling back to the first text content block (which
// is how mark3labs/mcp-go servers, including RepoKeeper, return tool output).
func resultJSON(res *mcp.CallToolResult) ([]byte, error) {
	if res.StructuredContent != nil {
		return json.Marshal(res.StructuredContent)
	}
	if text := resultText(res); text != "" {
		return []byte(text), nil
	}
	return nil, errors.New("repokeeper returned an empty result")
}

// resultText returns the concatenated text content of a tool result.
func resultText(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}
