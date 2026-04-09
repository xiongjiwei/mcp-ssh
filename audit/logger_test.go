package audit_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongjiwei/agent-sh/audit"
)

func newTestLogger(t *testing.T) (*audit.Logger, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	buf := &bytes.Buffer{}
	return audit.New(f, buf), buf, logPath
}

func TestLogger_Exec(t *testing.T) {
	l, buf, logPath := newTestLogger(t)
	l.LogExec("1.2.3.4", "alice", "srv1", "s1", "ls /tmp", "file1\nfile2\n", 0, 42)

	content, _ := os.ReadFile(logPath)
	if !strings.Contains(string(content), "EXEC: ls /tmp") {
		t.Errorf("missing EXEC line: %s", content)
	}
	if !strings.Contains(string(content), "EXIT:0") {
		t.Errorf("missing EXIT field: %s", content)
	}

	var ev map[string]any
	if err := json.NewDecoder(buf).Decode(&ev); err != nil {
		t.Fatal(err)
	}
	if ev["event"] != "exec" {
		t.Errorf("want event=exec, got %v", ev["event"])
	}
	if ev["command"] != "ls /tmp" {
		t.Errorf("want command=ls /tmp, got %v", ev["command"])
	}
	if ev["user"] != "alice" {
		t.Errorf("want user=alice, got %v", ev["user"])
	}
}

func TestLogger_ApprovalCycle(t *testing.T) {
	l, buf, logPath := newTestLogger(t)
	l.LogApprovalRequested("1.2.3.4", "alice", "srv1", "s1", "rm -rf /")
	l.LogApprovalDenied("1.2.3.4", "alice", "srv1", "s1", "rm -rf /")

	content, _ := os.ReadFile(logPath)
	if !strings.Contains(string(content), "APPROVAL: DENIED") {
		t.Errorf("missing denial line: %s", content)
	}

	dec := json.NewDecoder(buf)
	var e1, e2 map[string]any
	dec.Decode(&e1)
	dec.Decode(&e2)
	if e1["event"] != "approval_requested" {
		t.Errorf("want approval_requested, got %v", e1["event"])
	}
	if e2["event"] != "approval_denied" {
		t.Errorf("want approval_denied, got %v", e2["event"])
	}
}

func TestLogger_ApprovalApproved(t *testing.T) {
	l, buf, _ := newTestLogger(t)
	l.LogApprovalApproved("1.2.3.4", "alice", "srv1", "s1", "deploy.sh", 0, 100)

	var ev map[string]any
	json.NewDecoder(buf).Decode(&ev)
	if ev["event"] != "approval_approved" {
		t.Errorf("want approval_approved, got %v", ev["event"])
	}
}
