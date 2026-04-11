package approval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xiongjiwei/mcp-ssh/approval"
)

func newWebhook(transport string, timeoutSec int, action string) *approval.WebhookApprover {
	a := approval.NewApprover(approval.Config{
		Provider:  "webhook",
		Transport: transport,
		Webhook: approval.WebhookConfig{
			TimeoutSeconds: timeoutSec,
			TimeoutAction:  action,
		},
	})
	return a.(*approval.WebhookApprover)
}

// ── stdio warning log ─────────────────────────────────────────────────────────

func TestWebhook_StdioWarningLogged(t *testing.T) {
	var buf bytes.Buffer
	oldDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(oldDefault) })

	_ = approval.NewApprover(approval.Config{
		Provider:  "webhook",
		Transport: "stdio",
		Webhook:   approval.WebhookConfig{TimeoutSeconds: 300, TimeoutAction: "deny"},
	})
	if !strings.Contains(buf.String(), "webhook approval provider has no effect in stdio mode") {
		t.Errorf("expected slog.Warn about stdio mode, got: %s", buf.String())
	}
}

// ── stdio fast-path ──────────────────────────────────────────────────────────

func TestWebhook_StdioFastPath_Deny(t *testing.T) {
	wa := newWebhook("stdio", 300, "deny")
	dec, err := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "rm -rf /", "")
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Error("stdio fast-path with action=deny should return false")
	}
}

func TestWebhook_StdioFastPath_Allow(t *testing.T) {
	wa := newWebhook("stdio", 300, "allow")
	dec, err := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "rm -rf /", "")
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow {
		t.Error("stdio fast-path with action=allow should return true")
	}
}

// ── serve mode: timeout ──────────────────────────────────────────────────────

func TestWebhook_Timeout_Deny(t *testing.T) {
	wa := newWebhook("serve", 1, "deny")
	start := time.Now()
	dec, err := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "abc123")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Error("should deny on timeout")
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("should have waited ~1s, got %v", elapsed)
	}
}

func TestWebhook_Timeout_Allow(t *testing.T) {
	wa := newWebhook("serve", 1, "allow")
	dec, err := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow {
		t.Error("should allow on timeout when action=allow")
	}
}

// ── serve mode: ctx cancel ───────────────────────────────────────────────────

func TestWebhook_CtxCancel(t *testing.T) {
	wa := newWebhook("serve", 60, "deny")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		dec, err := wa.RequestApproval(ctx, "u", "h", "", "cmd", "ctxtest")
		if err == nil {
			t.Errorf("expected ctx error, got nil (allow=%v)", dec.Allow)
		}
		if dec.Allow {
			t.Error("should not allow on ctx cancel")
		}
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestApproval did not return after ctx cancel")
	}
}

// ── serve mode: decision allow ───────────────────────────────────────────────

func TestWebhook_DecisionAllow(t *testing.T) {
	wa := newWebhook("serve", 10, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	result := make(chan approval.Decision, 1)
	go func() {
		dec, _ := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "cmd", "deadbeef")
		result <- dec
	}()

	// Wait for request to be pending
	var id string
	for i := 0; i < 20; i++ {
		time.Sleep(10 * time.Millisecond)
		resp, err := http.Get(srv.URL + "/approval/pending")
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Requests []struct {
				ID string `json:"id"`
			} `json:"requests"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if len(body.Requests) > 0 {
			id = body.Requests[0].ID
			if id != "deadbeef" {
				t.Errorf("expected id=deadbeef (digest), got %q", id)
			}
			break
		}
	}
	if id == "" {
		t.Fatal("no pending request appeared")
	}

	body, _ := json.Marshal(map[string]any{"id": id, "allow": true, "reason": "looks safe"})
	resp, err := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case dec := <-result:
		if !dec.Allow {
			t.Error("expected allow")
		}
		if dec.Reason != "looks safe" {
			t.Errorf("expected reason='looks safe', got %q", dec.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestApproval did not return")
	}
}

func TestWebhook_DecisionDeny(t *testing.T) {
	wa := newWebhook("serve", 10, "allow")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	result := make(chan approval.Decision, 1)
	go func() {
		dec, _ := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "denytest")
		result <- dec
	}()

	var id string
	for i := 0; i < 20; i++ {
		time.Sleep(10 * time.Millisecond)
		resp, _ := http.Get(srv.URL + "/approval/pending")
		var body struct {
			Requests []struct{ ID string `json:"id"` } `json:"requests"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if len(body.Requests) > 0 {
			id = body.Requests[0].ID
			break
		}
	}
	if id == "" {
		t.Fatal("no pending request")
	}

	body, _ := json.Marshal(map[string]any{"id": id, "allow": false, "reason": "too dangerous"})
	http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(body))

	select {
	case dec := <-result:
		if dec.Allow {
			t.Error("expected deny")
		}
		if dec.Reason != "too dangerous" {
			t.Errorf("expected reason='too dangerous', got %q", dec.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// ── HTTP handler edge cases ───────────────────────────────────────────────────

func TestWebhook_Decision_UnknownID(t *testing.T) {
	wa := newWebhook("serve", 10, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"id": "nonexistent", "allow": true})
	resp, _ := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestWebhook_Decision_EmptyID(t *testing.T) {
	wa := newWebhook("serve", 10, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{"id": "", "allow": true})
	resp, _ := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("empty id should be 404, got %d", resp.StatusCode)
	}
}

func TestWebhook_Decision_MalformedBody(t *testing.T) {
	wa := newWebhook("serve", 10, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, _ := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader([]byte("not json")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhook_Pending_ImmediateWhenRequestExists(t *testing.T) {
	wa := newWebhook("serve", 10, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	go wa.RequestApproval(context.Background(), "u", "h", "ip", "cmd", "dg1") //nolint
	time.Sleep(20 * time.Millisecond)

	resp, _ := http.Get(srv.URL + "/approval/pending")
	var body struct {
		Requests []struct {
			ID       string `json:"id"`
			User     string `json:"user"`
			Host     string `json:"host"`
			RemoteIP string `json:"remote_ip"`
			Command  string `json:"command"`
		} `json:"requests"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()

	if len(body.Requests) == 0 {
		t.Fatal("expected at least one pending request")
	}
	r := body.Requests[0]
	if r.User != "u" || r.Host != "h" || r.RemoteIP != "ip" || r.Command != "cmd" {
		t.Errorf("unexpected request fields: %+v", r)
	}
	if r.ID != "dg1" {
		t.Errorf("expected id=dg1 (digest), got %q", r.ID)
	}
}

// ── concurrent race test ──────────────────────────────────────────────────────

func TestWebhook_Concurrent(t *testing.T) {
	wa := newWebhook("serve", 5, "deny")
	mux := http.NewServeMux()
	wa.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	const n = 5
	results := make(chan approval.Decision, n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			dec, _ := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", fmt.Sprintf("dg%d", i))
			results <- dec
		}()
	}

	approved := 0
	deadline := time.Now().Add(4 * time.Second)
	for approved < n && time.Now().Before(deadline) {
		resp, err := http.Get(srv.URL + "/approval/pending")
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var body struct {
			Requests []struct {
				ID string `json:"id"`
			} `json:"requests"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()

		for _, req := range body.Requests {
			b, _ := json.Marshal(map[string]any{"id": req.ID, "allow": true})
			http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(b)) //nolint
			approved++
		}
		time.Sleep(10 * time.Millisecond)
	}

	for i := 0; i < n; i++ {
		select {
		case <-results:
		case <-time.After(6 * time.Second):
			t.Fatalf("goroutine %d did not return", i)
		}
	}
}
