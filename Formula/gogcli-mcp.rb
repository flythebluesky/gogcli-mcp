class GogcliMcp < Formula
  desc "MCP server for Google Workspace via gog CLI - connects to Claude Co-Work"
  homepage "https://github.com/flythebluesky/gogcli-mcp"
  url "https://github.com/flythebluesky/gogcli-mcp/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "UPDATE_WITH_REAL_SHA256"
  license "MIT"

  depends_on "go" => :build
  depends_on "steipete/tap/gogcli"

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/gogcli-mcp"
  end

  def caveats
    <<~EOS
      To get started, run:
        gogcli-mcp setup

      This will check your gog accounts, generate OAuth credentials,
      and set up the server to start automatically on login.
    EOS
  end

  test do
    assert_match "gogcli-mcp", shell_output("#{bin}/gogcli-mcp 2>&1", 1)
  end
end
