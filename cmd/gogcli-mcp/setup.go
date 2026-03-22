package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gogcli-mcp/pkg/mcpauth"
)

func runSetup() {
	if runtime.GOOS != "darwin" {
		fmt.Println("Setup wizard currently supports macOS only.")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	configDir := os.Getenv("GOG_MCP_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join(home, ".config", "gogcli-mcp")
	}
	os.MkdirAll(configDir, 0700)

	// Step 1: Check gog
	fmt.Print("Checking for gog CLI... ")
	gogVersion, err := checkGog()
	if err != nil {
		fmt.Println("\u2717 not found.")
		fmt.Println("Install it with: brew tap steipete/tap && brew install gogcli")
		fmt.Println("Then run `gogcli-mcp setup` again.")
		os.Exit(1)
	}
	fmt.Printf("\u2713 found (%s)\n", gogVersion)

	// Step 2: Check accounts
	fmt.Print("Checking Google accounts... ")
	accounts, err := checkAccounts()
	if err != nil || len(accounts) == 0 {
		fmt.Println("\u2717 No Google accounts found.")
		fmt.Println("Run: gog auth add --readonly --service gmail,calendar,tasks")
		fmt.Println("Then run `gogcli-mcp setup` again.")
		os.Exit(1)
	}
	fmt.Printf("\u2713 %d account(s)\n", len(accounts))
	for _, a := range accounts {
		fmt.Printf("  \u2022 %s (%s)\n", a.Email, strings.Join(a.Services, ", "))
	}

	// Step 3: Generate OAuth client
	store := mcpauth.NewStore(filepath.Join(configDir, "oauth.json"))
	clients := store.GetClients()

	var client *mcpauth.Client
	if len(clients) > 0 {
		client = clients[0]
		fmt.Printf("\nExisting OAuth client: %s\n", client.ID)
	} else {
		client = store.RegisterClient("Claude Co-Work", []string{
			"https://claude.ai/api/mcp/auth_callback",
			"https://claude.com/api/mcp/auth_callback",
		})
		fmt.Println("\nOAuth client credentials generated.")
	}

	// Step 4: Ask for public URL
	fmt.Println("\nCo-Work cannot connect to localhost. You need a tunnel to expose")
	fmt.Println("the server with a public URL. Recommended options:")
	fmt.Println()
	fmt.Println("  Cloudflare Tunnel (recommended)")
	fmt.Println("    Requires a domain (~$10/yr) with DNS on Cloudflare.")
	fmt.Println("    Permanent URL, free tier, no interstitials.")
	fmt.Println("    https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/")
	fmt.Println()
	fmt.Println("  Tailscale Funnel")
	fmt.Println("    Free permanent URL (machine.tailnet.ts.net). Requires Tailscale.")
	fmt.Println("    https://tailscale.com/kb/1223/funnel")
	fmt.Println()
	fmt.Println("  Note: ngrok free tier is NOT compatible. Its browser interstitial")
	fmt.Println("  page breaks the OAuth authorization flow.")
	fmt.Println()
	fmt.Println("Set up a tunnel that points to https://localhost:9247, then enter")
	fmt.Println("the public URL below. Leave blank to skip (you can set GOG_MCP_ISSUER later).")
	fmt.Println()
	fmt.Print("Public URL: ")
	scanner.Scan()
	publicURL := strings.TrimSpace(scanner.Text())
	publicURL = strings.TrimRight(publicURL, "/")

	issuer := "https://localhost:9247"
	if publicURL != "" {
		if !strings.HasPrefix(publicURL, "https://") {
			fmt.Println("Error: public URL must start with https://")
			os.Exit(1)
		}
		issuer = publicURL
	}

	// Step 5: Write config file
	cfgData, _ := json.MarshalIndent(map[string]string{
		"transport":     "http",
		"addr":          ":9247",
		"issuer":        issuer,
		"client_id":     client.ID,
		"client_secret": client.Secret,
	}, "", "  ")
	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgData, 0600); err != nil {
		fmt.Printf("Failed to write config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nConfig written to %s\n", cfgPath)

	// Step 6: Print summary
	fmt.Println()
	fmt.Println("\u2705 Setup complete!")
	fmt.Println()
	fmt.Printf("Server:    %s\n", issuer)
	fmt.Printf("Client ID: %s\n", client.ID)
	fmt.Printf("Secret:    %s\n", client.Secret)
	fmt.Println()
	fmt.Println("Start the server with:")
	fmt.Println("  brew services start gogcli-mcp")
	fmt.Println()
	fmt.Println("To connect Claude Co-Work:")
	fmt.Printf("  1. Go to Settings > Connectors > Add custom connector\n")
	fmt.Printf("  2. Enter URL: %s/mcp\n", issuer)
	fmt.Println("  3. Click Advanced settings")
	fmt.Println("  4. Paste the Client ID and Secret above")
	fmt.Println("  5. Click Add")
	fmt.Println("  6. Approve access in the browser when prompted")
	fmt.Println()
	fmt.Println("To check status:")
	fmt.Println("  brew services info gogcli-mcp")
}

func checkGog() (string, error) {
	out, err := exec.Command("gog", "version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

type gogAccount struct {
	Email    string   `json:"email"`
	Services []string `json:"services"`
}

type gogAuthList struct {
	Accounts []gogAccount `json:"accounts"`
}

func checkAccounts() ([]gogAccount, error) {
	out, err := exec.Command("gog", "auth", "list", "--json").Output()
	if err != nil {
		return nil, err
	}
	var result gogAuthList
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, err
	}
	return result.Accounts, nil
}
