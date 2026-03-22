package gog

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/mark3labs/mcp-go/mcp"
)

// ShlexSplit splits a string into tokens respecting single and double quotes
// and backslash escapes, similar to Python's shlex.split.
func ShlexSplit(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if (r == ' ' || r == '\t') && !inSingle && !inDouble {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in: %s", s)
	}
	if escaped {
		return nil, fmt.Errorf("trailing backslash in: %s", s)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}

// Execute runs a gog command and returns the result as an MCP tool result.
func Execute(ctx context.Context, gogPath, service, command, args string) (*mcp.CallToolResult, error) {
	argv := []string{service}
	if command != "" {
		argv = append(argv, strings.Fields(command)...)
	}
	if args != "" {
		extraArgs, err := ShlexSplit(args)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid args: %v", err)), nil
		}
		argv = append(argv, extraArgs...)
	}
	argv = append(argv, "--json", "--force", "--no-input")

	cmd := exec.CommandContext(ctx, gogPath, argv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		}
		msg := fmt.Sprintf("gog %s failed (exit %d)", service, exitCode)
		if stderr.Len() > 0 {
			msg += "\n" + stderr.String()
		}
		if stdout.Len() > 0 {
			msg += "\n" + stdout.String()
		}
		return mcp.NewToolResultError(msg), nil
	}

	output := stdout.String()
	if output == "" {
		output = "OK (no output)"
	}
	return mcp.NewToolResultText(output), nil
}
