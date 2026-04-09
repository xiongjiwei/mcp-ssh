package mcp

import "context"

type ctxKey struct{}
type remoteIPKey struct{}

// WithMCPSessionID returns a new context carrying the given MCP session ID.
func WithMCPSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// MCPSessionIDFromCtx extracts the MCP session ID from ctx.
// Returns "" if not set.
func MCPSessionIDFromCtx(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// WithRemoteIP returns a new context carrying the client's remote IP.
func WithRemoteIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, remoteIPKey{}, ip)
}

// RemoteIPFromCtx extracts the remote IP from ctx.
// Returns "" if not set (e.g. stdio mode).
func RemoteIPFromCtx(ctx context.Context) string {
	ip, _ := ctx.Value(remoteIPKey{}).(string)
	return ip
}
