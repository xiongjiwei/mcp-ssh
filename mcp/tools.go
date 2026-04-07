package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/xiongjiwei/agent-sh/audit"
	"github.com/xiongjiwei/agent-sh/config"
	"github.com/xiongjiwei/agent-sh/daemon"
)

// Tools holds the dependencies shared by all tool handlers.
type Tools struct {
	sm     *daemon.SessionManager
	gate   *audit.ApprovalGate
	logger *audit.Logger
	cfg    *config.Config
}

func NewTools(sm *daemon.SessionManager, gate *audit.ApprovalGate, logger *audit.Logger, cfg *config.Config) *Tools {
	return &Tools{sm: sm, gate: gate, logger: logger, cfg: cfg}
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

	timeoutSec := t.cfg.Session.CommandTimeoutSeconds
	if args := req.GetArguments(); args != nil {
		if v, ok := args["timeout"]; ok {
			if n, ok := v.(float64); ok && n > 0 {
				timeoutSec = int(n)
			}
		}
	}

	// Session must already exist — exec does not auto-open.
	sess := t.sm.Get(host)
	if sess == nil {
		return errResult(fmt.Sprintf("no open session for %s — call open first", host)), nil
	}

	// Approval check
	allowed, approvalErr := t.gate.Check(ctx, host, sess.ID(), command)
	if approvalErr != nil || !allowed {
		t.logger.LogApprovalRequested(host, sess.ID(), command)
		t.logger.LogApprovalDenied(host, sess.ID(), command)
		return errResult("command denied by user"), nil
	}

	// Execute
	start := time.Now()
	stdout, exitCode, execErr := sess.Exec(command, time.Duration(timeoutSec)*time.Second)
	durationMs := time.Since(start).Milliseconds()

	if execErr != nil {
		// Execution error (timeout, session invalid) — log as exec error, not approval denial
		t.logger.LogExec(host, sess.ID(), command, "", 1, durationMs)
		return errResult(execErr.Error()), nil
	}

	t.logger.LogExec(host, sess.ID(), command, stdout, exitCode, durationMs)

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

	sess, err := t.sm.GetOrCreate(host)
	if err != nil {
		return errResult(fmt.Sprintf("failed to connect to %s: %v", host, err)), nil
	}

	text := fmt.Sprintf("session_id: %s\nhost: %s\nstate: ready", sess.ID(), host)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: text}},
	}, nil
}

// HandleClose implements the close MCP tool.
func (t *Tools) HandleClose(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host, err := req.RequireString("host")
	if err != nil {
		return okResult("closed"), nil
	}

	if t.sm.Get(host) == nil {
		return okResult(fmt.Sprintf("no active session for %s", host)), nil
	}
	t.sm.Close(host)
	return okResult("closed"), nil
}

// HandleStatus implements the status MCP tool.
func (t *Tools) HandleStatus(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	infos := t.sm.List()
	if len(infos) == 0 {
		return okResult("no active sessions"), nil
	}
	var sb strings.Builder
	for _, s := range infos {
		fmt.Fprintf(&sb, "host: %-20s session_id: %-12s idle: %ds   state: %s\n",
			s.Host, s.SessionID, s.IdleSeconds, s.State)
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
