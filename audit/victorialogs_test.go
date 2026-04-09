package audit_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongjiwei/agent-sh/audit"
)

func TestVictoriaLogsWriter_SendsData(t *testing.T) {
	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/insert/jsonline" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received <- buf
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := audit.NewVictoriaLogsWriter(srv.URL)
	payload := []byte(`{"event":"exec"}` + "\n")
	w.Write(payload)

	select {
	case got := <-received:
		if string(got) != string(payload) {
			t.Errorf("want %q, got %q", payload, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestVictoriaLogsWriter_DropsWhenFull(t *testing.T) {
	// Server that never responds (blocks), so channel fills up.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	w := audit.NewVictoriaLogsWriter(srv.URL)
	payload := []byte(`{"event":"exec"}` + "\n")

	// Fill channel beyond capacity (1000) — must not block or panic.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1100; i++ {
			w.Write(payload)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked when channel was full")
	}
}

func TestVictoriaLogsWriter_RetriesOnFailure(t *testing.T) {
	var attempts atomic.Int32
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		received <- struct{}{}
	}))
	defer srv.Close()

	w := audit.NewVictoriaLogsWriter(srv.URL)
	w.Write([]byte(`{"event":"exec"}` + "\n"))

	select {
	case <-received:
		if attempts.Load() != 3 {
			t.Errorf("want 3 attempts, got %d", attempts.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for successful delivery after retries")
	}
}

func TestVictoriaLogsWriter_DropsAfterMaxRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	w := audit.NewVictoriaLogsWriter(srv.URL)
	w.Write([]byte(`{"event":"exec"}` + "\n"))

	// Give time for all retries to exhaust (100ms + 200ms delays = 300ms total wait).
	time.Sleep(1200 * time.Millisecond)
	if attempts.Load() != 3 {
		t.Errorf("want 3 attempts, got %d", attempts.Load())
	}
}
