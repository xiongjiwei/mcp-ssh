package ssh

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
)

// Connector wraps a system ssh process attached to a PTY.
type Connector struct {
	cmd      *exec.Cmd
	ptmx     *os.File
	sentinel string
}

// New launches sshBin connecting to host (e.g. "ssh" "myserver").
// If host is empty, the binary is invoked with no arguments (for testing with "sh").
func New(sshBin, host string, connectTimeout time.Duration) (*Connector, error) {
	var cmd *exec.Cmd
	if host == "" {
		cmd = exec.Command(sshBin)
	} else {
		cmd = exec.Command(sshBin, "-tt", host)
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}

	sentinel, err := generateSentinel()
	if err != nil {
		ptmx.Close()
		cmd.Process.Kill()
		return nil, fmt.Errorf("sentinel: %w", err)
	}

	c := &Connector{cmd: cmd, ptmx: ptmx, sentinel: sentinel}

	// Inject sentinel and PS1 in a single atomic line.
	// Double-quoted PS1 embeds the sentinel value at assignment time,
	// portable across bash, zsh, and sh.
	initLine := fmt.Sprintf(
		`export __AGENT_SH_SENTINEL__="%s"; export PS1="${__AGENT_SH_SENTINEL__}"$'\n'`+"\n",
		sentinel,
	)
	if _, err := io.WriteString(ptmx, initLine); err != nil {
		ptmx.Close()
		cmd.Process.Kill()
		return nil, fmt.Errorf("write init: %w", err)
	}

	if err := c.waitForSentinel(connectTimeout); err != nil {
		ptmx.Close()
		cmd.Process.Kill()
		return nil, err
	}
	return c, nil
}

func (c *Connector) Sentinel() string { return c.sentinel }
func (c *Connector) PTY() *os.File    { return c.ptmx }

func (c *Connector) Close() error {
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
	return c.ptmx.Close()
}

func (c *Connector) waitForSentinel(timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(c.ptmx)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), c.sentinel) {
				done <- nil
				return
			}
		}
		done <- fmt.Errorf("PTY closed before sentinel appeared")
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("connect timeout: sentinel not seen within %s", timeout)
	}
}

func generateSentinel() (string, error) {
	out, err := exec.Command("sh", "-c",
		`cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen`,
	).Output()
	if err != nil {
		return "", err
	}
	return "agentsh_" + strings.TrimSpace(string(out)), nil
}
