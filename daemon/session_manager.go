package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/xiongjiwei/agent-sh/config"
	agentssh "github.com/xiongjiwei/agent-sh/ssh"
)

// SessionInfo is a snapshot of a session for status reporting.
type SessionInfo struct {
	User        string
	Host        string
	SessionID   string
	IdleSeconds int
	State       string
}

type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session // key: host
	cfg      *config.Config
	sshBin   string
}

func NewSessionManager(cfg *config.Config, sshBin string) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		cfg:      cfg,
		sshBin:   sshBin,
	}
	go sm.reapLoop()
	return sm
}

// newID generates a random 8-character hex ID.
func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GetOrCreate returns the existing valid session for host, or opens a new one.
func (sm *SessionManager) GetOrCreate(user, host string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.sessions[host]; ok && !s.IsInvalid() {
		return s, nil
	}

	timeout := time.Duration(sm.cfg.Session.ConnectTimeoutSeconds) * time.Second
	conn, err := agentssh.New(sm.sshBin, host, user, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", host, err)
	}

	id := newID()
	s := NewSession(user, host, id, conn, sm.cfg.Session.MaxOutputBytes)
	sm.sessions[host] = s
	return s, nil
}

// Get returns the existing session for host, or nil if none exists.
func (sm *SessionManager) Get(host string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.sessions[host]
}

// Close closes and removes the session for host.
func (sm *SessionManager) Close(host string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[host]; ok {
		s.Close()
		delete(sm.sessions, host)
	}
}

// CloseAll closes all sessions (used on shutdown).
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for host, s := range sm.sessions {
		s.Close()
		delete(sm.sessions, host)
	}
}

// List returns a snapshot of all sessions.
func (sm *SessionManager) List() []SessionInfo {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	result := make([]SessionInfo, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		state := "idle"
		if s.IsInvalid() {
			state = "invalid"
		} else if s.IsExecuting() {
			state = "executing"
		}
		result = append(result, SessionInfo{
			User:        s.User(),
			Host:        s.Host(),
			SessionID:   s.ID(),
			IdleSeconds: int(time.Since(s.LastActivity()).Seconds()),
			State:       state,
		})
	}
	return result
}

// Reap closes sessions that have exceeded the idle timeout.
func (sm *SessionManager) Reap() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.reap()
}

func (sm *SessionManager) reap() {
	timeout := time.Duration(sm.cfg.Session.IdleTimeoutMinutes) * time.Minute
	now := time.Now()
	for host, s := range sm.sessions {
		if now.Sub(s.LastActivity()) > timeout {
			s.Close()
			delete(sm.sessions, host)
		}
	}
}

func (sm *SessionManager) reapLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		sm.mu.Lock()
		sm.reap()
		sm.mu.Unlock()
	}
}
