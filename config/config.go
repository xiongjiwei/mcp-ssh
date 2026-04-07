package config

import (
	"errors"
	"os"

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
				"ls", "pwd", "cat", "echo", "grep", "find",
				"head", "tail", "ps", "df", "du", "uname",
				"whoami", "env", "cd",
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	_, err := toml.DecodeFile(path, cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, err
	}
	return cfg, nil
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.agent-sh/config.toml"
}
