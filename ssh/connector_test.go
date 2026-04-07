package ssh_test

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	agentssh "github.com/xiongjiwei/agent-sh/ssh"
)

func TestConnector_ConnectsAndSentinelAppears(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	// Use "sh" with no host arg as a local shell stand-in
	conn, err := agentssh.New("sh", "", 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer conn.Close()

	if conn.Sentinel() == "" {
		t.Error("sentinel must be non-empty")
	}
	if !strings.HasPrefix(conn.Sentinel(), "agentsh_") {
		t.Errorf("sentinel wrong prefix: %s", conn.Sentinel())
	}
}
