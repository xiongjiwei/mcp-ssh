package audit_test

import (
	"context"
	"testing"

	"github.com/xiongjiwei/agent-sh/approval"
	"github.com/xiongjiwei/agent-sh/audit"
)

func gate(whitelist []string) *audit.ApprovalGate {
	return audit.NewApprovalGate(whitelist, approval.NewApprover("auto_deny"))
}

func TestGate_Whitelisted_NoApprovalNeeded(t *testing.T) {
	g := gate([]string{"ls", "grep", "cat"})
	ok, err := g.Check(context.Background(), "srv1", "s1", "ls -la /etc")
	if err != nil || !ok {
		t.Errorf("whitelisted command should pass: ok=%v err=%v", ok, err)
	}
}

func TestGate_PathNormalized(t *testing.T) {
	g := gate([]string{"ls"})
	ok, err := g.Check(context.Background(), "srv1", "s1", "/bin/ls -la")
	if err != nil || !ok {
		t.Errorf("/bin/ls should normalize to ls: ok=%v err=%v", ok, err)
	}
}

func TestGate_NotWhitelisted_AutoDeny(t *testing.T) {
	g := gate([]string{"ls"})
	ok, err := g.Check(context.Background(), "srv1", "s1", "rm -rf /data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("rm should be denied by AutoDenyApprover")
	}
}

func TestGate_CompoundAllWhitelisted(t *testing.T) {
	g := gate([]string{"ls", "grep"})
	ok, _ := g.Check(context.Background(), "srv1", "s1", "ls /tmp | grep foo")
	if !ok {
		t.Error("both tokens whitelisted, should pass")
	}
}

func TestGate_CompoundOneNotWhitelisted(t *testing.T) {
	g := gate([]string{"ls"})
	ok, _ := g.Check(context.Background(), "srv1", "s1", "ls /tmp && rm -rf /")
	if ok {
		t.Error("rm not whitelisted, should deny")
	}
}

func TestGate_AmbiguousPattern_Deny(t *testing.T) {
	g := gate([]string{"ls", "echo"})
	cases := []string{
		"echo $(ls)",
		"ls `pwd`",
		"{ ls; echo done; }",
	}
	for _, c := range cases {
		ok, _ := g.Check(context.Background(), "srv1", "s1", c)
		if ok {
			t.Errorf("ambiguous command should require approval (denied by auto_deny): %q", c)
		}
	}
}
