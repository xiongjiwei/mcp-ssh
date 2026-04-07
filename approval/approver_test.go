package approval_test

import (
	"context"
	"testing"

	"github.com/xiongjiwei/agent-sh/approval"
)

func TestAutoDenyApprover_AlwaysDenies(t *testing.T) {
	a := approval.NewApprover("auto_deny")
	ok, err := a.RequestApproval(context.Background(), "srv1", "rm -rf /")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("AutoDenyApprover should always deny")
	}
}

func TestAutoDenyApprover_RespectsContextCancellation(t *testing.T) {
	a := approval.NewApprover("auto_deny")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	// AutoDeny returns immediately regardless of ctx state — no error expected
	_, err := a.RequestApproval(ctx, "srv1", "rm -rf /")
	if err != nil {
		t.Fatalf("AutoDenyApprover should not return ctx error: %v", err)
	}
}

func TestNewApprover_UnknownProvider_FallsBackToAutoDeny(t *testing.T) {
	a := approval.NewApprover("unknown_provider")
	ok, _ := a.RequestApproval(context.Background(), "h", "cmd")
	if ok {
		t.Error("unknown provider should fall back to auto_deny")
	}
}
