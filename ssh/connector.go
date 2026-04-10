package ssh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Connector wraps a persistent shell process with stdin/stdout pipes.
// No PTY is used — output is clean (no echo, no ANSI escapes, no \r\n).
type Connector struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	sentinel string
}

// New launches a persistent shell via pipes, with stderr merged into stdout.
// Both local and remote paths use "bash --norc --noprofile" to suppress rc
// files, aliases, and motd/banner noise for clean, AI-friendly output.
// For local testing (host==""): sshBin -c "bash --norc --noprofile"
// For remote hosts: ssh ... user@host "bash --norc --noprofile"
func New(sshBin, host, user string, connectTimeout time.Duration) (*Connector, error) {
	var cmd *exec.Cmd
	if host == "" {
		cmd = exec.Command(sshBin, "-c", "bash --norc --noprofile")
	} else {
		target := user + "@" + host
		args := []string{
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=QUIET",
			"-T",
			target,
			"bash --norc --noprofile",
		}
		cmd = exec.Command(sshBin, args...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	// After StdoutPipe(), cmd.Stdout holds the pipe's write end.
	// Point stderr to the same pipe so all output comes through one reader.
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}

	sentinel, err := generateSentinel()
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("sentinel: %w", err)
	}

	c := &Connector{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   stdout,
		sentinel: sentinel,
	}

	// Verify the remote shell is alive before returning.
	if err := c.waitForReady(connectTimeout); err != nil {
		cmd.Process.Kill()
		return nil, err
	}

	return c, nil
}

func (c *Connector) Sentinel() string      { return c.sentinel }
func (c *Connector) Stdin() io.WriteCloser  { return c.stdin }
func (c *Connector) Stdout() io.ReadCloser  { return c.stdout }

func (c *Connector) Close() error {
	c.stdin.Close()
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
	return c.cmd.Wait()
}

// waitForReady sends an echo-sentinel command via stdin, then reads stdout
// until the sentinel appears, confirming the shell is alive and ready.
func (c *Connector) waitForReady(timeout time.Duration) error {
	initCmd := fmt.Sprintf("echo '%s'\n", c.sentinel)
	if _, err := io.WriteString(c.stdin, initCmd); err != nil {
		return fmt.Errorf("write init: %w", err)
	}

	ch := make(chan error, 1)
	go func() {
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := c.stdout.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if strings.Contains(string(buf), c.sentinel) {
					ch <- nil
					return
				}
			}
			if err != nil {
				ch <- fmt.Errorf("shell not ready: %w", err)
				return
			}
		}
	}()

	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("connect timeout: shell not ready within %s", timeout)
	}
}

func generateSentinel() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mcpssh_" + hex.EncodeToString(b), nil
}
