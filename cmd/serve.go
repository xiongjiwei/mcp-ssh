package cmd

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var addrFlag string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run MCP server over StreamableHTTP",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := resolveAddr(addrFlag, cfg.Server.Addr)
		httpSrv := server.NewStreamableHTTPServer(mcpSrv)
		return httpSrv.Start(addr)
	},
}

func init() {
	serveCmd.Flags().StringVar(&addrFlag, "addr", "", "listen address (e.g. :8080), overrides config")
}

// resolveAddr returns the effective listen address.
// Priority: flagAddr > cfgAddr > built-in default.
func resolveAddr(flagAddr, cfgAddr string) string {
	if flagAddr != "" {
		return flagAddr
	}
	if cfgAddr != "" {
		return cfgAddr
	}
	return "127.0.0.1:8080"
}
