package approval_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	ok, err := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "rm -rf /", "")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("stdio fast-path with action=deny should return false")
	}
}

func TestWebhook_StdioFastPath_Allow(t *testing.T) {
	wa := newWebhook("stdio", 300, "allow")
	ok, err := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "rm -rf /", "")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("stdio fast-path with action=allow should return true")
	}
}

// ── serve mode: timeout ──────────────────────────────────────────────────────

func TestWebhook_Timeout_Deny(t *testing.T) {
	wa := newWebhook("serve", 1, "deny")
	start := time.Now()
	ok, err := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "abc123")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should deny on timeout")
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("should have waited ~1s, got %v", elapsed)
	}
}

func TestWebhook_Timeout_Allow(t *testing.T) {
	wa := newWebhook("serve", 1, "allow")
	ok, err := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
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
		ok, err := wa.RequestApproval(ctx, "u", "h", "", "cmd", "")
		if err == nil {
			t.Errorf("expected ctx error, got nil (ok=%v)", ok)
		}
		if ok {
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

	result := make(chan bool, 1)
	go func() {
		ok, _ := wa.RequestApproval(context.Background(), "u", "h", "1.2.3.4", "cmd", "deadbeef")
		result <- ok
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
				ID     string `json:"id"`
				Digest string `json:"digest"`
			} `json:"requests"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if len(body.Requests) > 0 {
			id = body.Requests[0].ID
			if body.Requests[0].Digest != "deadbeef" {
				t.Errorf("expected digest=deadbeef, got %q", body.Requests[0].Digest)
			}
			break
		}
	}
	if id == "" {
		t.Fatal("no pending request appeared")
	}

	dec, _ := json.Marshal(map[string]any{"id": id, "allow": true})
	resp, err := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(dec))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case ok := <-result:
		if !ok {
			t.Error("expected allow")
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

	result := make(chan bool, 1)
	go func() {
		ok, _ := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "")
		result <- ok
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

	dec, _ := json.Marshal(map[string]any{"id": id, "allow": false})
	http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(dec))

	select {
	case ok := <-result:
		if ok {
			t.Error("expected deny")
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

	dec, _ := json.Marshal(map[string]any{"id": "nonexistent", "allow": true})
	resp, _ := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(dec))
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

	dec, _ := json.Marshal(map[string]any{"id": "", "allow": true})
	resp, _ := http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(dec))
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

	// Put a request in flight
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
			Digest   string `json:"digest"`
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
	if r.Digest != "dg1" {
		t.Errorf("expected digest=dg1, got %q", r.Digest)
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
	results := make(chan bool, n)

	// Launch n concurrent approval requests
	for i := 0; i < n; i++ {
		go func() {
			ok, _ := wa.RequestApproval(context.Background(), "u", "h", "", "cmd", "")
			results <- ok
		}()
	}

	// Poll and approve all
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
			dec, _ := json.Marshal(map[string]any{"id": req.ID, "allow": true})
			http.Post(srv.URL+"/approval/decision", "application/json", bytes.NewReader(dec)) //nolint
			approved++
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Collect results (remaining may timeout to deny)
	for i := 0; i < n; i++ {
		select {
		case <-results:
		case <-time.After(6 * time.Second):
			t.Fatalf("goroutine %d did not return", i)
		}
	}
}
