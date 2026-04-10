package daemon_test

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xiongjiwei/mcp-ssh/daemon"
	agentssh "github.com/xiongjiwei/mcp-ssh/ssh"
)

func newTestSession(t *testing.T) *daemon.Session {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	conn, err := agentssh.New("bash", "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	return daemon.NewSession("testuser", "testhost", "test-id", conn, 1048576)
}

func TestSession_SimpleExec(t *testing.T) {
	s := newTestSession(t)
	defer s.Close()

	out, code, err := s.Exec("echo hello", 10*time.Second)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if code != 0 {
		t.Errorf("want exit 0, got %d", code)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("want 'hello' in output, got %q", out)
	}
}

func TestSession_ExitCodeCaptured(t *testing.T) {
	s := newTestSession(t)
	defer s.Close()

	_, code, err := s.Exec("bash -c 'exit 3'", 10*time.Second)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if code != 3 {
		t.Errorf("want exit 3, got %d", code)
	}
}

func TestSession_StatePersistedAcrossCalls(t *testing.T) {
	s := newTestSession(t)
	defer s.Close()

	if _, _, err := s.Exec("cd /tmp", 5*time.Second); err != nil {
		t.Fatalf("cd: %v", err)
	}
	out, _, err := s.Exec("pwd", 5*time.Second)
	if err != nil {
		t.Fatalf("pwd: %v", err)
	}
	if !strings.Contains(out, "/tmp") {
		t.Errorf("want /tmp in pwd output, got %q", out)
	}
}

func TestSession_OutputTruncated(t *testing.T) {
	s := newTestSession(t)
	defer s.Close()
	s.SetMaxOutputBytes(50)

	out, _, err := s.Exec("printf '%0.s-' $(seq 1 200)", 10*time.Second)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "[truncated]") {
		t.Errorf("want [truncated] suffix, got %q", out)
	}
}

func TestSession_InvalidAfterClose(t *testing.T) {
	s := newTestSession(t)
	s.Close()

	_, _, err := s.Exec("echo hi", 5*time.Second)
	if err == nil {
		t.Error("want error after close")
	}
}
