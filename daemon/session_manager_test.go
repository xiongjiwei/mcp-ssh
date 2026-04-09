package daemon_test

import (
	"testing"
	"time"

	"github.com/xiongjiwei/agent-sh/config"
	"github.com/xiongjiwei/agent-sh/daemon"
)

func newTestSM(t *testing.T) *daemon.SessionManager {
	t.Helper()
	cfg := config.Default()
	return daemon.NewSessionManager(cfg, "bash")
}

func TestSM_GetOrCreate_NewSession(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	s, err := sm.GetOrCreate("stdio", "", "")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if s == nil {
		t.Fatal("want non-nil session")
	}
}

func TestSM_GetOrCreate_Reuses(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	s1, _ := sm.GetOrCreate("stdio", "", "")
	s2, _ := sm.GetOrCreate("stdio", "", "")
	if s1.ID() != s2.ID() {
		t.Error("want same session on second call")
	}
}

func TestSM_Close_RemovesSession(t *testing.T) {
	sm := newTestSM(t)
	sm.GetOrCreate("stdio", "", "")
	sm.Close("stdio", "")

	s2, _ := sm.GetOrCreate("stdio", "", "")
	if s2 == nil {
		t.Fatal("want new session after close")
	}
}

func TestSM_List(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	sm.GetOrCreate("stdio", "", "")

	infos := sm.List("stdio")
	if len(infos) != 1 {
		t.Errorf("want 1 session, got %d", len(infos))
	}
}

func TestSM_IdleReap(t *testing.T) {
	sm := newTestSM(t)
	s, _ := sm.GetOrCreate("stdio", "", "")
	id := s.ID()

	// Force expiry
	s.SetLastActivity(time.Now().Add(-24 * time.Hour))
	sm.Reap()

	s2, _ := sm.GetOrCreate("stdio", "", "")
	if s2.ID() == id {
		t.Error("want new session after idle reap")
	}
}

func TestSM_Isolation_DifferentMCPSession(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	// Agent A opens a session on host ""
	s1, err := sm.GetOrCreate("agent-a", "", "")
	if err != nil {
		t.Fatalf("agent-a GetOrCreate: %v", err)
	}

	// Agent B cannot see agent-a's session
	got := sm.Get("agent-b", "")
	if got != nil {
		t.Error("agent-b should not see agent-a's session")
	}

	// Agent A can still see its own session
	got = sm.Get("agent-a", "")
	if got == nil {
		t.Error("agent-a should see its own session")
	}
	if got.ID() != s1.ID() {
		t.Errorf("want same session ID, got %s vs %s", got.ID(), s1.ID())
	}
}

func TestSM_Isolation_List(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	sm.GetOrCreate("agent-a", "", "")
	sm.GetOrCreate("agent-b", "", "")

	infosA := sm.List("agent-a")
	if len(infosA) != 1 {
		t.Errorf("agent-a: want 1 session, got %d", len(infosA))
	}

	infosB := sm.List("agent-b")
	if len(infosB) != 1 {
		t.Errorf("agent-b: want 1 session, got %d", len(infosB))
	}
}

func TestSM_Isolation_CloseDoesNotAffectOther(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	sm.GetOrCreate("agent-a", "", "")
	sm.GetOrCreate("agent-b", "", "")

	// Agent A closes its session
	sm.Close("agent-a", "")

	// Agent B's session is unaffected
	got := sm.Get("agent-b", "")
	if got == nil {
		t.Error("agent-b session should still exist after agent-a closes its session")
	}
}
