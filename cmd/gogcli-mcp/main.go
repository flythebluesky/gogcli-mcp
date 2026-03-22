package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"gogcli-mcp/internal/gog"
	"gogcli-mcp/internal/server"
	"gogcli-mcp/pkg/mcpauth"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		runSetup()
		return
	}
	runServer()
}

func runServer() {
	gogPath := os.Getenv("GOG_PATH")
	if gogPath == "" {
		gogPath = "gog"
	}

	schemaCmd := exec.Command(gogPath, "schema")
	schemaData, err := schemaCmd.Output()
	if err != nil {
		log.Fatalf("failed to run 'gog schema': %v", err)
	}

	schema, err := gog.ParseSchema(schemaData)
	if err != nil {
		log.Fatalf("failed to parse gog schema: %v", err)
	}

	groups := gog.DiscoverServiceGroups(schema)

	s := mcpserver.NewMCPServer(
		"gogcli-mcp",
		"0.1.0",
		mcpserver.WithToolCapabilities(false),
	)

	for _, sg := range groups {
		description := gog.BuildToolDescription(sg)
		commandPaths := gog.CollectLeafCommandPaths(sg)

		tool := mcp.NewTool(
			"gog_"+sg.Name,
			mcp.WithDescription(description),
			mcp.WithString("command",
				mcp.Required(),
				mcp.Description("Subcommand to run"),
				mcp.Enum(commandPaths...),
			),
			mcp.WithString("args",
				mcp.Description("Additional flags and arguments"),
			),
		)

		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			command, err := req.RequireString("command")
			if err != nil {
				return mcp.NewToolResultError("missing required parameter: command"), nil
			}
			args, _ := req.GetArguments()["args"].(string)
			return gog.Execute(ctx, gogPath, sg.Name, command, args)
		})
	}

	fmt.Fprintf(os.Stderr, "gogcli-mcp: registered %d tools from gog %s\n", len(groups), schema.Build)

	transport := os.Getenv("GOG_MCP_TRANSPORT")
	if transport == "http" {
		addr := os.Getenv("GOG_MCP_ADDR")
		if addr == "" {
			addr = ":9247"
		}

		issuer := os.Getenv("GOG_MCP_ISSUER")
		if issuer == "" {
			issuer = "https://localhost" + addr
		}

		configDir := os.Getenv("GOG_MCP_CONFIG_DIR")
		if configDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			configDir = filepath.Join(home, ".config", "gogcli-mcp")
		}

		store := mcpauth.NewStore(filepath.Join(configDir, "oauth.json"))

		coworkRedirects := []string{
			"https://claude.ai/api/mcp/auth_callback",
			"https://claude.com/api/mcp/auth_callback",
		}

		// Register client from env vars if provided.
		if envID := os.Getenv("GOG_MCP_CLIENT_ID"); envID != "" {
			if envSecret := os.Getenv("GOG_MCP_CLIENT_SECRET"); envSecret != "" {
				store.EnsureClient(envID, envSecret, "Claude Co-Work", coworkRedirects)
			}
		}

		// Auto-generate a client if none exist, so the server works out of the box.
		if clients := store.GetClients(); len(clients) == 0 {
			c := store.RegisterClient("Claude Co-Work", coworkRedirects)
			fmt.Fprintf(os.Stderr, "gogcli-mcp: generated OAuth client\n")
			fmt.Fprintf(os.Stderr, "gogcli-mcp:   Client ID: %s\n", c.ID)
			fmt.Fprintf(os.Stderr, "gogcli-mcp:   Secret:    %s\n", c.Secret)
		}

		oauthHandler := mcpauth.NewHandler(store, issuer, mcpauth.WithResourceDescription("your gog tools"))
		mcpHandler := mcpserver.NewStreamableHTTPServer(s)

		mux := http.NewServeMux()

		mux.Handle("/.well-known/oauth-authorization-server", oauthHandler)
		mux.Handle("/authorize", oauthHandler)
		mux.Handle("/token", oauthHandler)

		mux.Handle("/.well-known/oauth-protected-resource", oauthHandler)
		mux.Handle("/mcp", mcpauth.Middleware(store, issuer, mcpHandler))

		// Wrap with request logging
		logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(os.Stderr, "gogcli-mcp: %s %s\n", r.Method, r.URL.String())
			mux.ServeHTTP(w, r)
		})

		certFile, keyFile, err := server.EnsureCerts(
			os.Getenv("GOG_MCP_TLS_CERT"),
			os.Getenv("GOG_MCP_TLS_KEY"),
			configDir,
		)
		if err != nil {
			log.Fatalf("TLS setup: %v", err)
		}

		fmt.Fprintf(os.Stderr, "gogcli-mcp: HTTPS server listening on %s/mcp\n", addr)
		if err := http.ListenAndServeTLS(addr, certFile, keyFile, logged); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		if err := mcpserver.ServeStdio(s); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}
