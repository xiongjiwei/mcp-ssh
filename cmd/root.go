package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
	"github.com/xiongjiwei/mcp-ssh/approval"
	"github.com/xiongjiwei/mcp-ssh/audit"
	"github.com/xiongjiwei/mcp-ssh/config"
	"github.com/xiongjiwei/mcp-ssh/daemon"
	mcpsrv "github.com/xiongjiwei/mcp-ssh/mcp"
)

var (
	cfgPath  string
	mcpSrv   *server.MCPServer
	cfg      *config.Config
	approver approval.Approver
)

var rootCmd = &cobra.Command{
	Use:   "mcp-ssh",
	Short: "MCP server for remote shell execution via SSH",
	// Default (no subcommand): run stdio mode.
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := initDeps("stdio"); err != nil {
			return err
		}
		return runStdio()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultPath(), "path to config file")
	rootCmd.AddCommand(stdioCmd)
	rootCmd.AddCommand(serveCmd)
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initDeps builds the shared object graph from config.
// transport is "stdio" or "serve" and is forwarded to the approval provider.
func initDeps(transport string) error {
	var err error
	cfg, err = config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".mcp-ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	sm := daemon.NewSessionManager(cfg, "ssh")
	logWriter := &lumberjack.Logger{
		Filename: filepath.Join(dir, "audit.log"),
		MaxSize:  cfg.Audit.MaxSizeMB,
		MaxAge:   cfg.Audit.MaxAgeDays,
		Compress: cfg.Audit.Compress,
	}
	var jsonOut io.Writer = io.Discard
	if cfg.Audit.VictoriaLogsURL != "" {
		jsonOut = audit.NewVictoriaLogsWriter(cfg.Audit.VictoriaLogsURL)
	}
	logger := audit.New(logWriter, jsonOut)
	approver = approval.NewApprover(approval.Config{
		Provider:  cfg.Approval.Provider,
		Transport: transport,
		Webhook: approval.WebhookConfig{
			TimeoutSeconds: cfg.Approval.Webhook.TimeoutSeconds,
			TimeoutAction:  cfg.Approval.Webhook.TimeoutAction,
		},
	})
	gate := audit.NewApprovalGate(cfg.Approval.Whitelist, approver)
	tools := mcpsrv.NewTools(sm, gate, logger, cfg, transport)
	mcpSrv = mcpsrv.NewServer(tools)
	return nil
}
