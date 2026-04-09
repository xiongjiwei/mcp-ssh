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
	Provider  string   `toml:"provider"`
	Whitelist []string `toml:"whitelist"`
	IFlow     IFlowConfig `toml:"iflow"`
}

// IFlowConfig holds configuration for the iFlow approver.
type IFlowConfig struct {
	Endpoint   string `toml:"endpoint"`
	APIKey     string `toml:"api_key"`
	PollPeriod int    `toml:"poll_period_seconds"`
}

type Config struct {
	Session  SessionConfig  `toml:"session"`
	Approval ApprovalConfig `toml:"approval"`
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

// DefaultPath returns the default config file path under the user's home
// directory. If the home directory cannot be determined, it falls back to a
// relative path ".agent-sh/config.toml".
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".agent-sh", "config.toml")
	}
	return filepath.Join(home, ".agent-sh", "config.toml")
}
