# CLAUDE.md

## Project

gogcli-mcp is an MCP server that wraps the [gog](https://gogcli.sh) CLI to expose Google Workspace services as tools for Claude Co-Work.

## Project Structure

```
cmd/gogcli-mcp/main.go       Entry point, subcommand dispatch (setup vs server)
internal/gog/schema.go        gog schema parsing, service group discovery
internal/gog/executor.go      gog command execution, shell argument splitting
internal/server/certs.go      Auto-generated TLS certificates for localhost
pkg/mcpauth/                  Reusable OAuth 2.1 package for MCP servers (no DCR)
```

## Build & Test

```bash
make build          # builds ./gogcli-mcp from cmd/gogcli-mcp
make run            # builds + runs HTTPS server on :9247
go test ./...       # runs all tests (mcpauth package)
```

## Key Design Decisions

- `pkg/mcpauth` is a standalone reusable package — do not add gog-specific logic there
- `internal/` packages are gog-specific and not importable outside this module
- OAuth uses pre-registered clients only (no DCR) — clients provide client_id + secret
- Server always uses HTTPS; certs auto-generated if not provided
- OAuth state (clients, tokens) persists to `~/.config/gogcli-mcp/oauth.json`
- Access tokens: 1 hour. Refresh tokens: 1 year. Both configurable.
- Token endpoint supports both `client_secret_post` and `client_secret_basic` auth

## Environment Variables

- `GOG_MCP_TRANSPORT=http` — enables HTTPS server mode (default: stdio)
- `GOG_MCP_ADDR` — listen address (default: `:9247`)
- `GOG_MCP_ISSUER` — public URL for OAuth metadata (default: `https://localhost:<port>`)
- `GOG_MCP_CLIENT_ID` / `GOG_MCP_CLIENT_SECRET` — pre-register an OAuth client on startup
- `GOG_MCP_CONFIG_DIR` — config directory (default: `~/.config/gogcli-mcp`)
- `GOG_MCP_TLS_CERT` / `GOG_MCP_TLS_KEY` — custom TLS certs (default: auto-generated)
- `GOG_PATH` — path to gog binary (default: `gog`)
