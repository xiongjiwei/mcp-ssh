package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewServer creates and registers all MCP tools, returning a ready-to-serve MCPServer.
func NewServer(tools *Tools) *server.MCPServer {
	s := server.NewMCPServer("agent-sh", "1.0.0",
		server.WithToolCapabilities(false),
	)

	s.AddTool(
		mcp.NewTool("exec",
			mcp.WithDescription("Execute a shell command on a remote host. The session must be opened first with `open`. Commands run in the same persistent shell — cd, export, and other state changes persist across calls. If the command is not on the approved whitelist, it will be denied."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Remote host (must match an open session)")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Shell command to execute")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds for this call (default: 30)")),
		),
		tools.HandleExec,
	)

	s.AddTool(
		mcp.NewTool("open",
			mcp.WithDescription("Open a persistent SSH session to a remote host. Call this before exec. If a session already exists for the host, this is a no-op and returns the existing session info. Check status first to avoid redundant connections."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Remote host to connect to")),
		),
		tools.HandleOpen,
	)

	s.AddTool(
		mcp.NewTool("close",
			mcp.WithDescription("Close the SSH session for a host and release resources. Call when done with a host. Safe to call even if no session exists (idempotent)."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Remote host whose session to close")),
		),
		tools.HandleClose,
	)

	s.AddTool(
		mcp.NewTool("status",
			mcp.WithDescription("List all active SSH sessions with their current state. Call this first to check what sessions already exist before opening new ones. States: idle (ready for commands), invalid (session lost — call open to reconnect)."),
		),
		tools.HandleStatus,
	)

	return s
}
