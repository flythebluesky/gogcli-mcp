# CLAUDE.md

## Project

gogcli-mcp is an MCP server that wraps the [gog](https://gogcli.sh) CLI to expose Google Workspace services as tools for Claude Co-Work.

## Project Structure

```
cmd/gogcli-mcp/main.go       Entry point, subcommand dispatch (setup/version/server)
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

## Configuration

Server reads `~/.config/gogcli-mcp/config.json` for all settings. Env vars override config file values. The setup wizard (`gogcli-mcp setup`) generates this file.

```json
{
  "transport": "http",
  "addr": ":9247",
  "issuer": "https://gog.yourdomain.com",
  "client_id": "...",
  "client_secret": "..."
}
```

Config fields map to env vars: `transport` → `GOG_MCP_TRANSPORT`, `addr` → `GOG_MCP_ADDR`, `issuer` → `GOG_MCP_ISSUER`, etc. Additional env-only vars: `GOG_MCP_CONFIG_DIR` (default `~/.config/gogcli-mcp`), `GOG_PATH` (default `gog`).

## Service Management

Managed via Homebrew services (not manual launchd):

```bash
brew services start gogcli-mcp
brew services stop gogcli-mcp
brew services restart gogcli-mcp
brew services info gogcli-mcp
```

Logs: `/opt/homebrew/var/log/gogcli-mcp/`

## Key Design Decisions

- `pkg/mcpauth` is a standalone reusable package — do not add gog-specific logic there
- `internal/` packages are gog-specific and not importable outside this module
- OAuth uses pre-registered clients only (no DCR) — clients provide client_id + secret
- Server always uses HTTPS; certs auto-generated if not provided
- OAuth state (clients, tokens) persists to `~/.config/gogcli-mcp/oauth.json`
- Access tokens: 1 hour. Refresh tokens: 1 year. Both configurable.
- Token endpoint supports both `client_secret_post` and `client_secret_basic` auth

## Releasing

1. Tag: `git tag v1.x.0 && git push origin v1.x.0`
2. GitHub Actions builds binaries and creates a release automatically
3. Update Homebrew tap: in the `flythebluesky/homebrew-tap` repo, update `Formula/gogcli-mcp.rb` with the new version URL and SHA256:
   ```bash
   curl -sL https://github.com/flythebluesky/gogcli-mcp/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
   ```
4. Users upgrade with: `brew upgrade gogcli-mcp` (may need `brew untap/tap` if tap is cached)
