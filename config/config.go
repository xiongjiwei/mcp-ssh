package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type SessionConfig struct {
	IdleTimeoutMinutes    int `toml:"idle_timeout_minutes"`
	ConnectTimeoutSeconds int `toml:"connect_timeout_seconds"`
	CommandTimeoutSeconds int `toml:"command_timeout_seconds"`
	MaxOutputBytes        int `toml:"max_output_bytes"`
}

type ApprovalConfig struct {
	Provider  string      `toml:"provider"`
	Whitelist []string    `toml:"whitelist"`
	IFlow     IFlowConfig `toml:"iflow"`
}

type IFlowConfig struct {
	Endpoint   string `toml:"endpoint"`
	APIKey     string `toml:"api_key"`
	PollPeriod int    `toml:"poll_period_seconds"`
}

type ServerConfig struct {
	Addr string `toml:"addr"`
}

type AuditConfig struct {
	MaxSizeMB       int    `toml:"max_size_mb"`
	MaxAgeDays      int    `toml:"max_age_days"`
	Compress        bool   `toml:"compress"`
	VictoriaLogsURL string `toml:"victoria_logs_url"`
}

type Config struct {
	Session  SessionConfig  `toml:"session"`
	Approval ApprovalConfig `toml:"approval"`
	Server   ServerConfig   `toml:"server"`
	Audit    AuditConfig    `toml:"audit"`
}

func Default() *Config {
	return &Config{
		Session: SessionConfig{
			IdleTimeoutMinutes:    30,
			ConnectTimeoutSeconds: 15,
			CommandTimeoutSeconds: 30,
			MaxOutputBytes:        1048576,
		},
		Approval: ApprovalConfig{
			Provider: "auto_deny",
			Whitelist: []string{
				"ls", "pwd", "cat", "echo", "grep", "find", "wc",
				"head", "tail", "ps", "df", "du", "uname",
				"whoami", "env", "cd",
			},
		},
		Server: ServerConfig{
			Addr: "127.0.0.1:7408",
		},
		Audit: AuditConfig{
			MaxSizeMB:  128,
			MaxAgeDays: 3,
			Compress:   false,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, err
	}
	_, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".agent-sh", "config.toml")
	}
	return filepath.Join(home, ".agent-sh", "config.toml")
}
