package mcp_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/xiongjiwei/agent-sh/approval"
	"github.com/xiongjiwei/agent-sh/audit"
	"github.com/xiongjiwei/agent-sh/config"
	"github.com/xiongjiwei/agent-sh/daemon"
	agentmcp "github.com/xiongjiwei/agent-sh/mcp"
)


func newTestTools(t *testing.T) *agentmcp.Tools {
	t.Helper()
	cfg := config.Default()
	sm := daemon.NewSessionManager(cfg, "sh")
	logger := audit.New(os.DevNull, &bytes.Buffer{})
	gate := audit.NewApprovalGate(cfg.Approval.Whitelist, approval.NewApprover("auto_deny"))
	return agentmcp.NewTools(sm, gate, logger, cfg)
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
	req.Params.Arguments = map[string]any{"host": ""}
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
	openReq.Params.Arguments = map[string]any{"host": ""}
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
	openReq.Params.Arguments = map[string]any{"host": ""}
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
