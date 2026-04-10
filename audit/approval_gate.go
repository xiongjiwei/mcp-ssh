package audit

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/xiongjiwei/mcp-ssh/approval"
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
func (g *ApprovalGate) Check(ctx context.Context, user, host, sessionID, command string) (bool, error) {
	if g.isWhitelisted(command) {
		return true, nil
	}
	return g.approver.RequestApproval(ctx, user, host, command)
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
		strings.Contains(cmd, "{") ||
		strings.Contains(cmd, "<(") ||
		strings.Contains(cmd, ">(")
}

func splitCompound(cmd string) []string {
	var result []string
	var buf strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		switch c {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
			buf.WriteByte(c)
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
			buf.WriteByte(c)
		case '&':
			if !inSingleQuote && !inDoubleQuote {
				if i+1 < len(cmd) && cmd[i+1] == '&' {
					// && operator
					if buf.Len() > 0 {
						result = append(result, strings.TrimSpace(buf.String()))
						buf.Reset()
					}
					i++ // skip next &
				} else {
					buf.WriteByte(c)
				}
			} else {
				buf.WriteByte(c)
			}
		case '|':
			if !inSingleQuote && !inDoubleQuote {
				if i+1 < len(cmd) && cmd[i+1] == '|' {
					// || operator
					if buf.Len() > 0 {
						result = append(result, strings.TrimSpace(buf.String()))
						buf.Reset()
					}
					i++ // skip next |
				} else {
					// Single | (pipe)
					if buf.Len() > 0 {
						result = append(result, strings.TrimSpace(buf.String()))
						buf.Reset()
					}
				}
			} else {
				buf.WriteByte(c)
			}
		case ';':
			if !inSingleQuote && !inDoubleQuote {
				if buf.Len() > 0 {
					result = append(result, strings.TrimSpace(buf.String()))
					buf.Reset()
				}
			} else {
				buf.WriteByte(c)
			}
		default:
			buf.WriteByte(c)
		}
	}

	if buf.Len() > 0 {
		result = append(result, strings.TrimSpace(buf.String()))
	}

	return result
}
