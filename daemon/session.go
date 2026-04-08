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

// Session wraps a single persistent SSH pipe connection.
type Session struct {
	id           string
	user         string
	host         string
	conn         *agentssh.Connector
	maxOutput    int
	mu           sync.Mutex
	lastActivity time.Time
	invalid      bool
	executing    bool
}

func NewSession(user, host, id string, conn *agentssh.Connector, maxOutputBytes int) *Session {
	return &Session{
		id:           id,
		user:         user,
		host:         host,
		conn:         conn,
		maxOutput:    maxOutputBytes,
		lastActivity: time.Now(),
	}
}

func (s *Session) ID() string   { return s.id }
func (s *Session) User() string { return s.user }
func (s *Session) Host() string { return s.host }

func (s *Session) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActivity
}

func (s *Session) IsInvalid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.invalid
}

func (s *Session) IsExecuting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.executing
}

func (s *Session) SetMaxOutputBytes(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxOutput = n
}

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

	sentinel := s.conn.Sentinel()
	stdin := s.conn.Stdin()

	// Wrap command: capture exit code, then emit sentinel.
	s.executing = true
	defer func() { s.executing = false }()
	wrapped := fmt.Sprintf("%s; echo \"EXIT_CODE:$?\"; echo '%s'\n", cmd, sentinel)
	if _, err := io.WriteString(stdin, wrapped); err != nil {
		s.invalid = true
		return "", 1, fmt.Errorf("write to stdin: %w", err)
	}

	raw, err := s.readUntilSentinel(sentinel, timeout)
	if err != nil {
		return "", 1, err
	}

	s.lastActivity = time.Now()
	return s.parseOutput(raw)
}

// parseOutput extracts exit code and cleans the output string.
// Pipe mode means no echo, no ANSI, no \r\n — output is clean.
func (s *Session) parseOutput(raw string) (string, int, error) {
	lines := strings.Split(raw, "\n")

	exitCode := 0
	clean := make([]string, 0, len(lines))
	for _, l := range lines {
		if loc := exitCodeRe.FindStringSubmatchIndex(l); loc != nil {
			n, _ := strconv.Atoi(l[loc[2]:loc[3]])
			exitCode = n
			// Strip EXIT_CODE marker; keep any prefix content on the same line.
			prefix := strings.TrimRight(l[:loc[0]], " ")
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
	ch := make(chan result, 1)
	stdout := s.conn.Stdout()

	go func() {
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := stdout.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				// Search only the region where sentinel could start (tail of buffer).
				searchStart := len(buf) - n - len(sentinel)
				if searchStart < 0 {
					searchStart = 0
				}
				if idx := strings.Index(string(buf[searchStart:]), sentinel); idx >= 0 {
					ch <- result{out: string(buf[:searchStart+idx])}
					return
				}
			}
			if err != nil {
				ch <- result{err: fmt.Errorf("stdout read: %w", err)}
				return
			}
		}
	}()

	select {
	case res := <-ch:
		return res.out, res.err
	case <-time.After(timeout):
		// Send interrupt: write a newline + echo sentinel to try to re-sync.
		stdin := s.conn.Stdin()
		io.WriteString(stdin, "\x03\n")
		io.WriteString(stdin, fmt.Sprintf("echo '%s'\n", sentinel))
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			s.invalid = true
			s.conn.Close()
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
