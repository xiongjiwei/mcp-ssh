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
	return daemon.NewSessionManager(cfg, "sh")
}

func TestSM_GetOrCreate_NewSession(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	s, err := sm.GetOrCreate("localhost")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if s.Host() != "localhost" {
		t.Errorf("want localhost, got %s", s.Host())
	}
}

func TestSM_GetOrCreate_Reuses(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	s1, _ := sm.GetOrCreate("localhost")
	s2, _ := sm.GetOrCreate("localhost")
	if s1.ID() != s2.ID() {
		t.Error("want same session on second call")
	}
}

func TestSM_Close_RemovesSession(t *testing.T) {
	sm := newTestSM(t)
	sm.GetOrCreate("localhost")
	sm.Close("localhost")

	s2, _ := sm.GetOrCreate("localhost")
	if s2 == nil {
		t.Fatal("want new session after close")
	}
}

func TestSM_List(t *testing.T) {
	sm := newTestSM(t)
	defer sm.CloseAll()

	sm.GetOrCreate("host1")
	sm.GetOrCreate("host2")

	infos := sm.List()
	if len(infos) != 2 {
		t.Errorf("want 2 sessions, got %d", len(infos))
	}
}

func TestSM_IdleReap(t *testing.T) {
	sm := newTestSM(t)
	s, _ := sm.GetOrCreate("localhost")
	id := s.ID()

	// Force expiry
	s.SetLastActivity(time.Now().Add(-24 * time.Hour))
	sm.Reap()

	s2, _ := sm.GetOrCreate("localhost")
	if s2.ID() == id {
		t.Error("want new session after idle reap")
	}
}
