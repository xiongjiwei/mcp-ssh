package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/xiongjiwei/mcp-ssh/approval"
	"github.com/xiongjiwei/mcp-ssh/audit"
	"github.com/xiongjiwei/mcp-ssh/config"
	"github.com/xiongjiwei/mcp-ssh/session"
)

// Tools holds the dependencies shared by all tool handlers.
type Tools struct {
	sm             *session.Manager
	gate           *approval.Gate
	logger         *audit.Logger
	cfg            *config.Config
	stdioSessionID string
}

// NewTools constructs Tools. stdioSessionID is used when no MCP session ID is
// present in the context (stdio mode). Pass "stdio" for stdio mode, "" for
// serve mode (the context always carries the ID in serve mode).
func NewTools(sm *session.Manager, gate *approval.Gate, logger *audit.Logger, cfg *config.Config, stdioSessionID string) *Tools {
	return &Tools{sm: sm, gate: gate, logger: logger, cfg: cfg, stdioSessionID: stdioSessionID}
}

// mcpSessionID extracts the MCP session ID from ctx, falling back to
// stdioSessionID when the context carries no value (stdio mode).
func (t *Tools) mcpSessionID(ctx context.Context) string {
	if id := MCPSessionIDFromCtx(ctx); id != "" {
		return id
	}
	return t.stdioSessionID
}

// HandleExec implements the exec MCP tool.
func (t *Tools) HandleExec(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, err := req.RequireString("host")
	if err != nil {
		return errResult("host parameter required"), nil
	}
	command, err := req.RequireString("command")
	if err != nil {
		return errResult("command parameter required"), nil
	}
	description, _ := req.RequireString("description")
	timeoutSec := t.cfg.Session.CommandTimeoutSeconds
	if n, err := req.RequireInt("timeout"); err == nil && n > 0 {
		timeoutSec = n
	}

	mcpSessID := t.mcpSessionID(ctx)

	// Session must already exist — exec does not auto-open.
	sess := t.sm.Get(mcpSessID, host)
	if sess == nil {
		return errResult(fmt.Sprintf("no open session for %s — call open first", host)), nil
	}

	// Approval check
	remoteIP := RemoteIPFromCtx(ctx)
	digest := audit.CmdDigest(sess.ID(), command)

	cwd, _, cwdErr := sess.Exec("pwd", time.Duration(timeoutSec)*time.Second)
	if cwdErr != nil {
		cwd = ""
	}
	cwd = strings.TrimSpace(cwd)

	execReq := session.Request{
		User:        sess.User(),
		Host:        host,
		RemoteIP:    remoteIP,
		Command:     command,
		Description: description,
		Cwd:         cwd,
		Digest:      digest,
	}
	dec, approvalErr := t.gate.Check(ctx, sess.ID(), execReq)
	if approvalErr != nil {
		return nil, approvalErr
	}
	if !dec.Allow {
		return errResult("command denied: " + dec.Reason), nil
	}

	// Execute
	start := time.Now()
	stdout, exitCode, execErr := sess.Exec(command, time.Duration(timeoutSec)*time.Second)
	durationMs := time.Since(start).Milliseconds()

	if execErr != nil {
		t.logger.LogExec(sess.ID(), execReq, "", 1, durationMs)
		return errResult(execErr.Error()), nil
	}

	t.logger.LogExec(sess.ID(), execReq, stdout, exitCode, durationMs)

	content := []mcp.Content{
		mcp.TextContent{Type: "text", Text: stdout},
		mcp.TextContent{Type: "text", Text: fmt.Sprintf("exit_code: %d", exitCode)},
	}
	isErr := exitCode != 0
	return &mcp.CallToolResult{Content: content, IsError: isErr}, nil
}

// HandleOpen implements the open MCP tool.
func (t *Tools) HandleOpen(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, err := req.RequireString("host")
	if err != nil {
		return errResult("host parameter required"), nil
	}
	user, err := req.RequireString("user")
	if err != nil {
		return errResult("user parameter required"), nil
	}

	mcpSessID := t.mcpSessionID(ctx)

	sess, err := t.sm.GetOrCreate(mcpSessID, user, host)
	if err != nil {
		return errResult(fmt.Sprintf("failed to connect to %s: %v", host, err)), nil
	}

	t.logger.LogOpen(RemoteIPFromCtx(ctx), user, host, sess.ID())

	text := fmt.Sprintf("session_id: %s\nhost: %s\nstate: ready", sess.ID(), host)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: text}},
	}, nil
}

// HandleClose implements the close MCP tool.
func (t *Tools) HandleClose(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, err := req.RequireString("host")
	if err != nil {
		return okResult("closed"), nil
	}

	mcpSessID := t.mcpSessionID(ctx)
	sess := t.sm.Get(mcpSessID, host)
	t.sm.Close(mcpSessID, host)
	if sess != nil {
		t.logger.LogClose(RemoteIPFromCtx(ctx), sess.User(), host, sess.ID())
	}
	return okResult("closed"), nil
}

// HandleStatus implements the status MCP tool.
func (t *Tools) HandleStatus(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	infos := t.sm.List(t.mcpSessionID(ctx))
	if len(infos) == 0 {
		return okResult("no active sessions"), nil
	}
	var sb strings.Builder
	for _, s := range infos {
		fmt.Fprintf(&sb, "%s@%-20s session_id: %-12s idle: %ds   state: %s\n",
			s.User, s.Host, s.SessionID, s.IdleSeconds, s.State)
	}
	return okResult(strings.TrimRight(sb.String(), "\n")), nil
}

func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: msg}},
		IsError: true,
	}
}

func okResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: msg}},
	}
}
