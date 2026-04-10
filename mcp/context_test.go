package mcp_test

import (
	"context"
	"testing"

	agentmcp "github.com/xiongjiwei/mcp-ssh/mcp"
)

func TestMCPSessionID_RoundTrip(t *testing.T) {
	ctx := agentmcp.WithMCPSessionID(context.Background(), "abc123")
	got := agentmcp.MCPSessionIDFromCtx(ctx)
	if got != "abc123" {
		t.Errorf("want abc123, got %s", got)
	}
}

func TestMCPSessionID_Missing(t *testing.T) {
	got := agentmcp.MCPSessionIDFromCtx(context.Background())
	if got != "" {
		t.Errorf("want empty string, got %s", got)
	}
}
