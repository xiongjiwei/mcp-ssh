package audit

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	vlPath        = "/insert/jsonline"
	vlChanCap     = 1000
	vlMaxRetries  = 3
	vlHTTPTimeout = 5 * time.Second
)

// VictoriaLogsWriter is an io.Writer that ships each written payload to
// VictoriaLogs via HTTP POST. Writes are non-blocking: if the internal
// channel is full the payload is silently dropped. Delivery failures are
// retried up to vlMaxRetries times with exponential back-off before dropping.
type VictoriaLogsWriter struct {
	url    string
	ch     chan []byte
	client *http.Client
}

// NewVictoriaLogsWriter constructs a VictoriaLogsWriter and starts its
// background delivery goroutine. baseURL is the VictoriaLogs base URL
// (e.g. "http://host:9428"); the path "/insert/jsonline" is appended
// automatically.
func NewVictoriaLogsWriter(baseURL string) *VictoriaLogsWriter {
	w := &VictoriaLogsWriter{
		url:    baseURL + vlPath,
		ch:     make(chan []byte, vlChanCap),
		client: &http.Client{Timeout: vlHTTPTimeout},
	}
	go w.run()
	return w
}

// Write enqueues p for delivery. Returns immediately; drops silently if the
// channel is full. Always returns len(p), nil to satisfy io.Writer.
func (w *VictoriaLogsWriter) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case w.ch <- buf:
	default:
	}
	return len(p), nil
}

func (w *VictoriaLogsWriter) run() {
	for p := range w.ch {
		w.sendWithRetry(p)
	}
}

func (w *VictoriaLogsWriter) sendWithRetry(p []byte) {
	delay := 100 * time.Millisecond
	var lastErr error
	for i := range vlMaxRetries {
		if lastErr = w.send(p); lastErr == nil {
			return
		}
		if i < vlMaxRetries-1 {
			time.Sleep(delay)
			delay *= 2
		}
	}
	slog.Error("victorialogs: dropped event after retries", "err", lastErr, "url", w.url)
}

func (w *VictoriaLogsWriter) send(p []byte) error {
	resp, err := w.client.Post(w.url, "application/x-ndjson", bytes.NewReader(p))
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
