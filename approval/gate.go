package approval

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/xiongjiwei/mcp-ssh/audit"
)

// Gate checks commands against a whitelist, then calls the Approver
// for commands that are not whitelisted.
type Gate struct {
	whitelist map[string]struct{}
	approver  Approver
	logger    *audit.Logger
}

func NewGate(whitelist []string, approver Approver, logger *audit.Logger) *Gate {
	m := make(map[string]struct{}, len(whitelist))
	for _, w := range whitelist {
		m[w] = struct{}{}
	}
	return &Gate{whitelist: m, approver: approver, logger: logger}
}

// Check returns (Decision, nil) on success, (zero Decision, err) on approver failure.
// Whitelisted commands return Decision{Allow: true} without logging or calling the approver.
// Non-whitelisted commands are logged (requested → approved/denied) around the approver call.
func (g *Gate) Check(ctx context.Context, user, host, remoteIP, sessionID, command, digest string) (Decision, error) {
	if g.isWhitelisted(command) {
		return Decision{Allow: true}, nil
	}

	g.logger.LogApprovalRequested(remoteIP, user, host, sessionID, command, digest)

	dec, err := g.approver.RequestApproval(ctx, user, host, remoteIP, command, digest)
	g.logger.LogApprovalDecision(remoteIP, user, host, sessionID, command, digest, dec.Reason, dec.Allow && err == nil)
	return dec, err
}

func (g *Gate) isWhitelisted(command string) bool {
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

func (g *Gate) tokenWhitelisted(segment string) bool {
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
					if buf.Len() > 0 {
						result = append(result, strings.TrimSpace(buf.String()))
						buf.Reset()
					}
					i++ // skip next |
				} else {
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
