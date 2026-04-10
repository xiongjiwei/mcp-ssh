package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	agentmcp "github.com/xiongjiwei/mcp-ssh/mcp"
)

var addrFlag string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run MCP server over StreamableHTTP",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := resolveAddr(addrFlag, cfg.Server.Addr)

		vlStatus := "(disabled)"
		if cfg.Audit.VictoriaLogsURL != "" {
			vlStatus = cfg.Audit.VictoriaLogsURL
		}
		slog.Info("serving",
			"addr", addr,
			"audit", "~/.agent-sh/audit.log",
			"audit_mb", cfg.Audit.MaxSizeMB,
			"audit_days", cfg.Audit.MaxAgeDays,
			"approval", cfg.Approval.Provider,
			"victoria", vlStatus,
		)

		httpSrv := server.NewStreamableHTTPServer(mcpSrv,
			server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
				id := r.Header.Get("Mcp-Session-Id")
				ctx = agentmcp.WithMCPSessionID(ctx, id)
				if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					ctx = agentmcp.WithRemoteIP(ctx, ip)
				}
				return ctx
			}),
		)
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
	return cfgAddr
}
