package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/server"
	"github.com/xiongjiwei/agent-sh/approval"
	"github.com/xiongjiwei/agent-sh/audit"
	"github.com/xiongjiwei/agent-sh/config"
	"github.com/xiongjiwei/agent-sh/daemon"
	agentmcp "github.com/xiongjiwei/agent-sh/mcp"
)

func main() {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	dir := filepath.Join(os.Getenv("HOME"), ".agent-sh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir error: %v\n", err)
		os.Exit(1)
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
	srv := agentmcp.NewServer(tools)

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
