package approval_test

import (
	"context"
	"testing"

	"github.com/xiongjiwei/mcp-ssh/approval"
)

func TestAutoDenyApprover_AlwaysDenies(t *testing.T) {
	a := approval.NewApprover(approval.Config{Provider: "auto_deny"})
	ok, err := a.RequestApproval(context.Background(), "user", "srv1", "", "rm -rf /")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("AutoDenyApprover should always deny")
	}
}

func TestAutoDenyApprover_RespectsContextCancellation(t *testing.T) {
	a := approval.NewApprover(approval.Config{Provider: "auto_deny"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.RequestApproval(ctx, "user", "srv1", "", "rm -rf /")
	if err != nil {
		t.Fatalf("AutoDenyApprover should not return ctx error: %v", err)
	}
}

func TestNewApprover_UnknownProvider_FallsBackToAutoDeny(t *testing.T) {
	a := approval.NewApprover(approval.Config{Provider: "unknown_provider"})
	ok, _ := a.RequestApproval(context.Background(), "user", "h", "", "cmd")
	if ok {
		t.Error("unknown provider should fall back to auto_deny")
	}
}

func TestAutoAllowApprover_AlwaysAllows(t *testing.T) {
	a := approval.NewApprover(approval.Config{Provider: "auto_allow"})
	ok, err := a.RequestApproval(context.Background(), "user", "srv1", "", "rm -rf /")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("AutoAllowApprover should always allow")
	}
}
