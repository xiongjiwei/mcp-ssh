package mcp_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/xiongjiwei/mcp-ssh/approval"
	"github.com/xiongjiwei/mcp-ssh/audit"
	"github.com/xiongjiwei/mcp-ssh/config"
	"github.com/xiongjiwei/mcp-ssh/daemon"
	mcpsrv "github.com/xiongjiwei/mcp-ssh/mcp"
)


func newTestTools(t *testing.T) *mcpsrv.Tools {
	t.Helper()
	cfg := config.Default()
	sm := daemon.NewSessionManager(cfg, "bash")
	logger := audit.New(io.Discard, &bytes.Buffer{})
	gate := audit.NewApprovalGate(cfg.Approval.Whitelist, approval.NewApprover(approval.Config{Provider: "auto_deny"}))
	return mcpsrv.NewTools(sm, gate, logger, cfg, "stdio")
}

func TestTools_Status_NoSessions(t *testing.T) {
	tools := newTestTools(t)
	req := mcp.CallToolRequest{}
	result, err := tools.HandleStatus(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Error("status should never be isError")
	}
	text := firstText(result)
	if text != "no active sessions" {
		t.Errorf("want 'no active sessions', got %q", text)
	}
}

func TestTools_Open_Success(t *testing.T) {
	tools := newTestTools(t)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"host": "", "user": ""}
	result, err := tools.HandleOpen(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("open failed: %s", firstText(result))
	}
}

func TestTools_Exec_NoSession_ReturnsError(t *testing.T) {
	tools := newTestTools(t)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"host": "nosuchsession", "command": "ls"}
	result, err := tools.HandleExec(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("exec without open session should be isError")
	}
}

func TestTools_Exec_WhitelistedCommand(t *testing.T) {
	tools := newTestTools(t)
	ctx := context.Background()

	// Open first
	openReq := mcp.CallToolRequest{}
	openReq.Params.Arguments = map[string]any{"host": "", "user": ""}
	tools.HandleOpen(ctx, openReq)

	// Exec whitelisted command
	execReq := mcp.CallToolRequest{}
	execReq.Params.Arguments = map[string]any{"host": "", "command": "echo hello"}
	result, err := tools.HandleExec(ctx, execReq)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("whitelisted exec failed: %s", firstText(result))
	}
	// content[1] should be exit_code: 0
	if len(result.Content) < 2 {
		t.Fatalf("want 2 content blocks, got %d", len(result.Content))
	}
}

func TestTools_Exec_NotWhitelisted_AutoDeny(t *testing.T) {
	tools := newTestTools(t)
	ctx := context.Background()

	openReq := mcp.CallToolRequest{}
	openReq.Params.Arguments = map[string]any{"host": "", "user": ""}
	tools.HandleOpen(ctx, openReq)

	execReq := mcp.CallToolRequest{}
	execReq.Params.Arguments = map[string]any{"host": "", "command": "rm -rf /"}
	result, _ := tools.HandleExec(ctx, execReq)
	if !result.IsError {
		t.Error("non-whitelisted command should be denied and isError")
	}
}

func TestTools_Close_Idempotent(t *testing.T) {
	tools := newTestTools(t)
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"host": "nonexistent"}
	result, err := tools.HandleClose(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Error("close should never be isError")
	}
}

// firstText extracts the text from the first content block.
func firstText(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestTools_Isolation_AgentCannotSeeOtherSession(t *testing.T) {
	cfg := config.Default()
	sm := daemon.NewSessionManager(cfg, "bash")
	logger := audit.New(io.Discard, &bytes.Buffer{})
	gate := audit.NewApprovalGate(cfg.Approval.Whitelist, approval.NewApprover(approval.Config{Provider: "auto_deny"}))

	toolsA := mcpsrv.NewTools(sm, gate, logger, cfg, "agent-a")
	toolsB := mcpsrv.NewTools(sm, gate, logger, cfg, "agent-b")

	// Agent A opens a session on host ""
	openReq := mcp.CallToolRequest{}
	openReq.Params.Arguments = map[string]any{"host": "", "user": ""}
	toolsA.HandleOpen(context.Background(), openReq)

	// Agent B tries to exec on the same host — should fail (no open session)
	execReq := mcp.CallToolRequest{}
	execReq.Params.Arguments = map[string]any{"host": "", "command": "echo hello"}
	result, err := toolsB.HandleExec(context.Background(), execReq)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("agent-b should not be able to exec on agent-a's session")
	}
}
