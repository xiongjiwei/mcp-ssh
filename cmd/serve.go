package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/xiongjiwei/mcp-ssh/approval"
	mcpsrv "github.com/xiongjiwei/mcp-ssh/mcp"
)

var addrFlag string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run MCP server over StreamableHTTP",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return initDeps("serve")
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := resolveAddr(addrFlag, cfg.Server.Addr)

		vlStatus := "(disabled)"
		if cfg.Audit.VictoriaLogsURL != "" {
			vlStatus = cfg.Audit.VictoriaLogsURL
		}
		slog.Info("serving",
			"addr", addr,
			"audit", "~/.mcp-ssh/audit.log",
			"audit_mb", cfg.Audit.MaxSizeMB,
			"audit_days", cfg.Audit.MaxAgeDays,
			"approval", cfg.Approval.Provider,
			"victoria", vlStatus,
		)

		// Build a custom mux shared by webhook routes and the MCP endpoint.
		mux := http.NewServeMux()
		if wa, ok := approver.(*approval.WebhookApprover); ok {
			wa.RegisterHandlers(mux)
		}

		httpSrv := server.NewStreamableHTTPServer(mcpSrv,
			server.WithStreamableHTTPServer(&http.Server{Handler: mux}),
			server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
				id := r.Header.Get("Mcp-Session-Id")
				ctx = mcpsrv.WithMCPSessionID(ctx, id)
				if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
					ctx = mcpsrv.WithRemoteIP(ctx, ip)
				}
				return ctx
			}),
		)

		// Register the MCP endpoint on our mux manually.
		// (mcp-go's Start() only does this when it creates its own mux internally.)
		mux.Handle("/mcp", httpSrv)

		return httpSrv.Start(addr)
	},
}

func init() {
	serveCmd.Flags().StringVar(&addrFlag, "addr", "", "listen address (e.g. :8080), overrides config")
}

// resolveAddr returns the effective listen address.
func resolveAddr(flagAddr, cfgAddr string) string {
	if flagAddr != "" {
		return flagAddr
	}
	return cfgAddr
}
