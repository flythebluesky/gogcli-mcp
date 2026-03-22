package gog

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Schema is the top-level structure returned by `gog schema`.
type Schema struct {
	SchemaVersion int     `json:"schema_version"`
	Build         string  `json:"build"`
	Command       Command `json:"command"`
}

// Command represents a command or subcommand in the gog schema tree.
type Command struct {
	Name        string    `json:"name"`
	Aliases     []string  `json:"aliases,omitempty"`
	Help        string    `json:"help"`
	Path        string    `json:"path"`
	Usage       string    `json:"usage"`
	Flags       []Flag    `json:"flags,omitempty"`
	Subcommands []Command `json:"subcommands,omitempty"`
}

// Flag represents a flag on a gog command.
type Flag struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	Short       string   `json:"short,omitempty"`
	Help        string   `json:"help"`
	Type        string   `json:"type"`
	Default     string   `json:"default,omitempty"`
	HasDefault  bool     `json:"has_default,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
}

// ServiceGroup represents a top-level gog service (e.g. gmail, calendar, drive).
type ServiceGroup struct {
	Name         string
	Help         string
	LeafCommands []LeafCommand
}

// LeafCommand is a terminal command within a service group.
type LeafCommand struct {
	CommandPath string // space-separated subcommand path, e.g. "labels create"
	Help        string
	Usage       string
}

// ParseSchema parses the JSON output of `gog schema`.
func ParseSchema(data []byte) (*Schema, error) {
	var schema Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("parsing gog schema: %w", err)
	}
	return &schema, nil
}

// DiscoverServiceGroups walks the top-level subcommands and returns those
// that have their own subcommands (i.e., service groups like gmail, calendar).
func DiscoverServiceGroups(schema *Schema) []ServiceGroup {
	var groups []ServiceGroup
	for _, cmd := range schema.Command.Subcommands {
		if len(cmd.Subcommands) == 0 {
			continue
		}
		sg := ServiceGroup{
			Name: cmd.Name,
			Help: cmd.Help,
		}
		collectLeaves(&sg, cmd.Subcommands, "")
		if len(sg.LeafCommands) > 0 {
			groups = append(groups, sg)
		}
	}
	return groups
}

func collectLeaves(sg *ServiceGroup, cmds []Command, prefix string) {
	for _, cmd := range cmds {
		path := cmd.Name
		if prefix != "" {
			path = prefix + " " + cmd.Name
		}
		if len(cmd.Subcommands) == 0 {
			sg.LeafCommands = append(sg.LeafCommands, LeafCommand{
				CommandPath: path,
				Help:        cmd.Help,
				Usage:       cmd.Usage,
			})
		} else {
			collectLeaves(sg, cmd.Subcommands, path)
		}
	}
}

// BuildToolDescription generates a concise MCP tool description for a service group.
func BuildToolDescription(sg ServiceGroup) string {
	var b strings.Builder
	b.WriteString(sg.Help)
	b.WriteString("\n\nAvailable commands:\n")
	for _, lc := range sg.LeafCommands {
		fmt.Fprintf(&b, "  %s - %s\n", lc.CommandPath, lc.Help)
	}
	b.WriteString("\nPass the command as 'command' and any flags/arguments as 'args'.")
	return b.String()
}

// CollectLeafCommandPaths returns a flat list of all leaf command paths
// for use as enum values on the command parameter.
func CollectLeafCommandPaths(sg ServiceGroup) []string {
	paths := make([]string, len(sg.LeafCommands))
	for i, lc := range sg.LeafCommands {
		paths[i] = lc.CommandPath
	}
	return paths
}
