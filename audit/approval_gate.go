package audit

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/xiongjiwei/agent-sh/approval"
)

// ApprovalGate checks commands against a whitelist, then calls the Approver
// for commands that are not whitelisted.
type ApprovalGate struct {
	whitelist map[string]struct{}
	approver  approval.Approver
}

func NewApprovalGate(whitelist []string, approver approval.Approver) *ApprovalGate {
	m := make(map[string]struct{}, len(whitelist))
	for _, w := range whitelist {
		m[w] = struct{}{}
	}
	return &ApprovalGate{whitelist: m, approver: approver}
}

// Check returns (true, nil) if the command may execute.
// Returns (false, nil) if denied. Returns (false, err) on approver failure.
func (g *ApprovalGate) Check(ctx context.Context, host, sessionID, command string) (bool, error) {
	if g.isWhitelisted(command) {
		return true, nil
	}
	return g.approver.RequestApproval(ctx, host, command)
}

func (g *ApprovalGate) isWhitelisted(command string) bool {
	if containsAmbiguous(command) {
		return false
	}
	tokens := splitCompound(command)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !g.tokenWhitelisted(tok) {
			return false
		}
	}
	return true
}

func (g *ApprovalGate) tokenWhitelisted(segment string) bool {
	segment = strings.TrimSpace(segment)
	fields := strings.Fields(segment)
	if len(fields) == 0 {
		return true
	}
	name := filepath.Base(fields[0])
	_, ok := g.whitelist[name]
	return ok
}

func containsAmbiguous(cmd string) bool {
	return strings.Contains(cmd, "$(") ||
		strings.Contains(cmd, "`") ||
		strings.Contains(cmd, "{")
}

func splitCompound(cmd string) []string {
	cmd = strings.ReplaceAll(cmd, "&&", "\x00")
	cmd = strings.ReplaceAll(cmd, "||", "\x00")
	cmd = strings.ReplaceAll(cmd, "|", "\x00")
	cmd = strings.ReplaceAll(cmd, ";", "\x00")
	parts := strings.Split(cmd, "\x00")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}
