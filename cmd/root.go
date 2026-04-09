package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/xiongjiwei/agent-sh/approval"
	"github.com/xiongjiwei/agent-sh/audit"
	"github.com/xiongjiwei/agent-sh/config"
	"github.com/xiongjiwei/agent-sh/daemon"
	agentmcp "github.com/xiongjiwei/agent-sh/mcp"
)

var (
	cfgPath string
	mcpSrv  *server.MCPServer
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "agent-sh",
	Short: "MCP server for remote shell execution via SSH",
	// Default (no subcommand): run stdio mode.
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStdio()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultPath(), "path to config file")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return initDeps()
	}
	rootCmd.AddCommand(stdioCmd)
	rootCmd.AddCommand(serveCmd)
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initDeps builds the shared object graph from config. Called before every subcommand.
func initDeps() error {
	var err error
	cfg, err = config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".agent-sh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	sm := daemon.NewSessionManager(cfg, "ssh")
	logger := audit.New(filepath.Join(dir, "audit.log"), os.Stderr)
	approver := approval.NewApprover(approval.Config{
		Provider:        cfg.Approval.Provider,
		IFlowEndpoint:   cfg.Approval.IFlow.Endpoint,
		IFlowAPIKey:     cfg.Approval.IFlow.APIKey,
		IFlowPollPeriod: cfg.Approval.IFlow.PollPeriod,
	})
	gate := audit.NewApprovalGate(cfg.Approval.Whitelist, approver)
	tools := agentmcp.NewTools(sm, gate, logger, cfg)
	mcpSrv = agentmcp.NewServer(tools)
	return nil
}
