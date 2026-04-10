package mcp_test

import (
	"context"
	"testing"

	mcpsrv "github.com/xiongjiwei/mcp-ssh/mcp"
)

func TestMCPSessionID_RoundTrip(t *testing.T) {
	ctx := mcpsrv.WithMCPSessionID(context.Background(), "abc123")
	got := mcpsrv.MCPSessionIDFromCtx(ctx)
	if got != "abc123" {
		t.Errorf("want abc123, got %s", got)
	}
}

func TestMCPSessionID_Missing(t *testing.T) {
	got := mcpsrv.MCPSessionIDFromCtx(context.Background())
	if got != "" {
		t.Errorf("want empty string, got %s", got)
	}
}
