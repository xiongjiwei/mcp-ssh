package daemon

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	agentssh "github.com/xiongjiwei/agent-sh/ssh"
)

var exitCodeRe = regexp.MustCompile(`EXIT_CODE:(\d+)`)

// Session wraps a single persistent SSH PTY connection.
type Session struct {
	id           string
	host         string
	conn         *agentssh.Connector
	maxOutput    int
	mu           sync.Mutex
	lastActivity time.Time
	invalid      bool
	executing    bool
}

func NewSession(host, id string, conn *agentssh.Connector, maxOutputBytes int) *Session {
	return &Session{
		id:           id,
		host:         host,
		conn:         conn,
		maxOutput:    maxOutputBytes,
		lastActivity: time.Now(),
	}
}

func (s *Session) ID() string              { return s.id }
func (s *Session) Host() string            { return s.host }
func (s *Session) LastActivity() time.Time { return s.lastActivity }
func (s *Session) IsInvalid() bool         { return s.invalid }
func (s *Session) IsExecuting() bool       { return s.executing }
func (s *Session) SetMaxOutputBytes(n int) { s.maxOutput = n }

// SetLastActivity is used in tests to force expiry.
func (s *Session) SetLastActivity(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = t
}

// Exec runs cmd and returns (stdout, exitCode, error).
func (s *Session) Exec(cmd string, timeout time.Duration) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.invalid {
		return "", 1, fmt.Errorf("session lost: shell process exited unexpectedly — state (cwd, env) may be lost; reconnect with the open tool")
	}

	ptmx := s.conn.PTY()
	sentinel := s.conn.Sentinel()

	// Wrap command with exit code capture.
	s.executing = true
	defer func() { s.executing = false }()
	if _, err := io.WriteString(ptmx, fmt.Sprintf("%s; echo \"EXIT_CODE:$?\"\n", cmd)); err != nil {
		s.invalid = true
		return "", 1, fmt.Errorf("write to PTY: %w", err)
	}

	raw, err := s.readUntilSentinel(sentinel, timeout)
	if err != nil {
		return "", 1, err
	}

	s.lastActivity = time.Now()
	return s.parseOutput(raw)
}

// parseOutput extracts exit code and cleans the output string.
// The raw PTY output has the following structure:
//   - Line 0: echoed command (PTY local echo)
//   - Subsequent lines: actual command output with \r\n line endings
//   - EXIT_CODE:\d+ may appear at the end of the last output line (no intervening newline)
//     when the command does not print a trailing newline.
func (s *Session) parseOutput(raw string) (string, int, error) {
	// Normalize CRLF to LF to handle PTY carriage returns.
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	lines := strings.Split(normalized, "\n")

	// Skip line 0: it is the echoed command text.
	if len(lines) > 0 {
		lines = lines[1:]
	}

	exitCode := 0
	clean := make([]string, 0, len(lines))
	for _, l := range lines {
		if loc := exitCodeRe.FindStringSubmatchIndex(l); loc != nil {
			n, _ := strconv.Atoi(l[loc[2]:loc[3]])
			exitCode = n
			// Strip EXIT_CODE marker; keep any prefix content on the same line.
			prefix := strings.TrimRight(l[:loc[0]], "\r")
			if prefix != "" {
				clean = append(clean, prefix)
			}
			continue
		}
		clean = append(clean, l)
	}
	stdout := strings.TrimRight(strings.Join(clean, "\n"), "\n") + "\n"
	if len(stdout) > s.maxOutput {
		stdout = stdout[:s.maxOutput] + "[truncated]"
	}
	return stdout, exitCode, nil
}

func (s *Session) readUntilSentinel(sentinel string, timeout time.Duration) (string, error) {
	type result struct {
		out string
		err error
	}
	// Buffered channel prevents goroutine leak: goroutine always sends once,
	// and the channel has capacity to receive even after the select has moved on.
	ch := make(chan result, 1)
	ptmx := s.conn.PTY()

	go func() {
		var buf strings.Builder
		tmp := make([]byte, 4096)
		for {
			n, err := ptmx.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
				if idx := strings.Index(buf.String(), sentinel); idx >= 0 {
					ch <- result{out: buf.String()[:idx]}
					return
				}
			}
			if err != nil {
				// PTY closed (e.g. via s.Close() or session invalidation) unblocks Read with an error.
				ch <- result{err: fmt.Errorf("PTY read: %w", err)}
				return
			}
		}
	}()

	select {
	case res := <-ch:
		return res.out, res.err
	case <-time.After(timeout):
		// Send Ctrl+C to interrupt hung command, then attempt re-sync.
		io.WriteString(ptmx, "\x03")
		io.WriteString(ptmx, "echo \"EXIT_CODE:$?\"\n")
		select {
		case <-ch: // re-sync succeeded; goroutine exited cleanly
		case <-time.After(5 * time.Second):
			// Re-sync failed: mark invalid and close PTY.
			// Closing PTY causes the blocked Read in the goroutine to return an error,
			// ensuring the goroutine exits and the channel is consumed.
			s.invalid = true
			ptmx.Close()
			<-ch // drain to let goroutine exit
		}
		return "", fmt.Errorf("command timeout after %s", timeout)
	}
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalid = true
	return s.conn.Close()
}
