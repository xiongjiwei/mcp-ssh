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

func TestDefault_ServerAddr(t *testing.T) {
	cfg := config.Default()
	if cfg.Server.Addr != "127.0.0.1:7408" {
		t.Errorf("want 127.0.0.1:7408, got %s", cfg.Server.Addr)
	}
}

func TestLoad_ServerAddr_FromTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(`
[server]
addr = "0.0.0.0:9090"
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "0.0.0.0:9090" {
		t.Errorf("want 0.0.0.0:9090, got %s", cfg.Server.Addr)
	}
}

func TestDefault_AuditConfig(t *testing.T) {
	cfg := config.Default()
	if cfg.Audit.MaxSizeMB != 128 {
		t.Errorf("want MaxSizeMB=128, got %d", cfg.Audit.MaxSizeMB)
	}
	if cfg.Audit.MaxAgeDays != 3 {
		t.Errorf("want MaxAgeDays=3, got %d", cfg.Audit.MaxAgeDays)
	}
	if cfg.Audit.Compress != false {
		t.Errorf("want Compress=false, got %v", cfg.Audit.Compress)
	}
}

func TestLoad_AuditConfig_FromTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(`
[audit]
max_size_mb  = 64
max_age_days = 7
compress     = true
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.MaxSizeMB != 64 {
		t.Errorf("want MaxSizeMB=64, got %d", cfg.Audit.MaxSizeMB)
	}
	if cfg.Audit.MaxAgeDays != 7 {
		t.Errorf("want MaxAgeDays=7, got %d", cfg.Audit.MaxAgeDays)
	}
	if cfg.Audit.Compress != true {
		t.Errorf("want Compress=true, got %v", cfg.Audit.Compress)
	}
}
