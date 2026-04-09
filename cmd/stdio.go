package cmd

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var stdioCmd = &cobra.Command{
	Use:   "stdio",
	Short: "Run MCP server over stdio (default mode)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStdio()
	},
}

func runStdio() error {
	return server.ServeStdio(mcpSrv)
}
