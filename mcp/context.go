package mcp

import "context"

type ctxKey struct{}

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
