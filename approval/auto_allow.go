package approval

import (
	"context"

	"github.com/xiongjiwei/mcp-ssh/session"
)

// AutoAllowApprover approves every request immediately.
// Use only in trusted environments where unrestricted command execution is acceptable.
type AutoAllowApprover struct{}

func (a *AutoAllowApprover) RequestApproval(_ context.Context, _ session.Request) (Decision, error) {
	return Decision{Allow: true}, nil
}
