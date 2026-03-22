BINARY    := gogcli-mcp
ADDR      := :9247

.PHONY: build run tunnel clean

build:
	go build -o $(BINARY) ./cmd/gogcli-mcp

run: build
	GOG_MCP_TRANSPORT=http GOG_MCP_ADDR=$(ADDR) ./$(BINARY)

# Expose local server to the internet via Cloudflare tunnel (no account needed)
tunnel: build
	GOG_MCP_TRANSPORT=http GOG_MCP_ADDR=$(ADDR) ./$(BINARY) & \
	sleep 1 && \
	cloudflared tunnel --url https://localhost$(ADDR)

clean:
	rm -rf $(BINARY)
