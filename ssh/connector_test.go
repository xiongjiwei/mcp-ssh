package ssh_test

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	agentssh "github.com/xiongjiwei/agent-sh/ssh"
)

func TestConnector_ConnectsAndSentinelAppears(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	conn, err := agentssh.New("bash", "", "", 5*time.Second)
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

func TestConnector_ConnectsAndSentinelAppearsOnRemoteHost(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	conn, err := agentssh.New("ssh", "example-host", "example-user", 5*time.Second)
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
