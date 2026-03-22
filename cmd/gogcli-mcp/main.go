package main

import (
	"context"
	"encoding/json"
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

type config struct {
	Transport    string `json:"transport"`
	Addr         string `json:"addr"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GogPath      string `json:"gog_path"`
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`
}

// loadConfig reads config.json from configDir. Missing file is not an error.
func loadConfig(configDir string) config {
	var cfg config
	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

// envOrConfig returns the env var value if set, otherwise the config file value.
func envOrConfig(envKey, cfgVal string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return cfgVal
}

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		runSetup()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	runServer()
}

func runServer() {
	configDir := os.Getenv("GOG_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("cannot determine home directory: %v", err)
		}
		configDir = filepath.Join(home, ".config", "gogcli-mcp")
	}

	cfg := loadConfig(configDir)

	gogPath := envOrConfig("GOG_PATH", cfg.GogPath)
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
		version,
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

	transport := envOrConfig("GOG_MCP_TRANSPORT", cfg.Transport)
	if transport == "http" {
		addr := envOrConfig("GOG_MCP_ADDR", cfg.Addr)
		if addr == "" {
			addr = ":9247"
		}

		issuer := envOrConfig("GOG_MCP_ISSUER", cfg.Issuer)
		if issuer == "" {
			issuer = "https://localhost" + addr
		}

		store := mcpauth.NewStore(filepath.Join(configDir, "oauth.json"))

		coworkRedirects := []string{
			"https://claude.ai/api/mcp/auth_callback",
			"https://claude.com/api/mcp/auth_callback",
		}

		// Register client from env vars or config if provided.
		clientID := envOrConfig("GOG_MCP_CLIENT_ID", cfg.ClientID)
		clientSecret := envOrConfig("GOG_MCP_CLIENT_SECRET", cfg.ClientSecret)
		if clientID != "" && clientSecret != "" {
			store.EnsureClient(clientID, clientSecret, "Claude Co-Work", coworkRedirects)
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

		tlsCert := envOrConfig("GOG_MCP_TLS_CERT", cfg.TLSCert)
		tlsKey := envOrConfig("GOG_MCP_TLS_KEY", cfg.TLSKey)
		certFile, keyFile, err := server.EnsureCerts(tlsCert, tlsKey, configDir)
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
