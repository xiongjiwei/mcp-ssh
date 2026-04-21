package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// pendingRequest holds an in-flight approval request waiting for an external decision.
type pendingRequest struct {
	ID       string
	User     string
	Host     string
	RemoteIP string
	Command  string
	result   chan Decision // buffered(1); written exactly once
}

// WebhookApprover implements Approver via HTTP long polling.
// In serve mode, callers poll GET /approval/pending and POST /approval/decision.
// In stdio mode, RequestApproval returns onTimeout immediately.
type WebhookApprover struct {
	mu        sync.Mutex
	pending   map[string]*pendingRequest
	notify    chan struct{} // closed and replaced on each new request
	timeout   time.Duration
	onTimeout bool   // true = allow on timeout
	transport string // "stdio" or "serve"
}

// RequestApproval blocks until an external decision arrives, the context is
// cancelled, or the timeout elapses.
func (a *WebhookApprover) RequestApproval(ctx context.Context, user, host, remoteIP, command, digest string) (Decision, error) {
	// stdio fast-path: no HTTP server, return configured timeout action immediately.
	if a.transport == "stdio" {
		return Decision{Allow: a.onTimeout}, nil
	}

	req := &pendingRequest{
		ID:       digest,
		User:     user,
		Host:     host,
		RemoteIP: remoteIP,
		Command:  command,
		result:   make(chan Decision, 1),
	}

	// Register and broadcast under the same lock so long-poll waiters never miss it.
	a.mu.Lock()
	a.pending[digest] = req
	old := a.notify
	a.notify = make(chan struct{})
	a.mu.Unlock()
	close(old) // broadcast: new request available

	t := time.NewTimer(a.timeout)
	select {
	case d := <-req.result:
		t.Stop()
		return d, nil
	case <-ctx.Done():
		t.Stop()
		a.mu.Lock()
		delete(a.pending, digest)
		a.mu.Unlock()
		return Decision{}, ctx.Err()
	case <-t.C:
		a.mu.Lock()
		delete(a.pending, digest)
		a.mu.Unlock()
		reason := "approval timed out: auto-denied"
		if a.onTimeout {
			reason = "approval timed out: auto-allowed"
		}
		return Decision{Allow: a.onTimeout, Reason: reason}, nil
	}
}

// RegisterHandlers registers the approval HTTP endpoints on mux.
// Call this only in serve mode before starting the HTTP server.
func (a *WebhookApprover) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/approval/pending", a.handlePending)
	mux.HandleFunc("/approval/decision", a.handleDecision)
}

// pendingItem is the JSON shape returned by GET /approval/pending.
// ID doubles as the audit digest — use it to correlate with audit log entries
// and as the key for POST /approval/decision.
type pendingItem struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Host     string `json:"host"`
	RemoteIP string `json:"remote_ip"`
	Command  string `json:"command"`
}

// pendingResponse is the top-level JSON envelope.
type pendingResponse struct {
	Requests []pendingItem `json:"requests"`
}

// snapshot returns a copy of the current pending list. Must be called under mu.
func (a *WebhookApprover) snapshot() []pendingItem {
	items := make([]pendingItem, 0, len(a.pending))
	for _, r := range a.pending {
		items = append(items, pendingItem{
			ID:       r.ID,
			User:     r.User,
			Host:     r.Host,
			RemoteIP: r.RemoteIP,
			Command:  r.Command,
		})
	}
	return items
}

// handlePending serves GET /approval/pending.
// It returns immediately if there are pending requests; otherwise it long-polls
// for up to 30 seconds waiting for a new request to arrive.
func (a *WebhookApprover) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.mu.Lock()
	items := a.snapshot()
	ch := a.notify
	a.mu.Unlock()

	if len(items) > 0 {
		writeJSON(w, items)
		return
	}

	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	select {
	case <-ch:
		a.mu.Lock()
		items = a.snapshot()
		a.mu.Unlock()
		writeJSON(w, items)
	case <-t.C:
		writeJSON(w, nil)
	}
}

// decisionRequest is the JSON body for POST /approval/decision.
type decisionRequest struct {
	ID     string `json:"id"`
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// handleDecision serves POST /approval/decision.
func (a *WebhookApprover) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var dec decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&dec); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Hold mu for the entire read+delete sequence to prevent TOCTOU with
	// RequestApproval's timeout/cancel cleanup arms.
	a.mu.Lock()
	req, ok := a.pending[dec.ID]
	if ok {
		delete(a.pending, dec.ID)
	}
	a.mu.Unlock()

	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	req.result <- Decision{Allow: dec.Allow, Reason: dec.Reason} // safe: buffered(1), receiver still alive
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, items []pendingItem) {
	w.Header().Set("Content-Type", "application/json")
	resp := pendingResponse{Requests: items}
	if items == nil {
		resp.Requests = []pendingItem{}
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
