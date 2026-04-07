package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xiongjiwei/agent-sh/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.Session.IdleTimeoutMinutes != 30 {
		t.Errorf("want 30, got %d", cfg.Session.IdleTimeoutMinutes)
	}
	if cfg.Session.ConnectTimeoutSeconds != 15 {
		t.Errorf("want 15, got %d", cfg.Session.ConnectTimeoutSeconds)
	}
	if cfg.Session.CommandTimeoutSeconds != 30 {
		t.Errorf("want 30, got %d", cfg.Session.CommandTimeoutSeconds)
	}
	if cfg.Session.MaxOutputBytes != 1048576 {
		t.Errorf("want 1048576, got %d", cfg.Session.MaxOutputBytes)
	}
	if cfg.Approval.Provider != "auto_deny" {
		t.Errorf("want auto_deny, got %s", cfg.Approval.Provider)
	}
	if len(cfg.Approval.Whitelist) == 0 {
		t.Error("want non-empty default whitelist")
	}
}

func TestLoad_OverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(`
[session]
idle_timeout_minutes = 10
[approval]
provider = "auto_deny"
whitelist = ["ls"]
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Session.IdleTimeoutMinutes != 10 {
		t.Errorf("want 10, got %d", cfg.Session.IdleTimeoutMinutes)
	}
	// unset fields keep defaults
	if cfg.Session.ConnectTimeoutSeconds != 15 {
		t.Errorf("want default 15, got %d", cfg.Session.ConnectTimeoutSeconds)
	}
	if len(cfg.Approval.Whitelist) != 1 {
		t.Errorf("want [ls], got %v", cfg.Approval.Whitelist)
	}
}

func TestLoad_MissingFile_ReturnsDefaults(t *testing.T) {
	cfg, err := config.Load("/nonexistent/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Session.IdleTimeoutMinutes != 30 {
		t.Error("want defaults when file missing")
	}
}
