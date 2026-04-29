package approval

import (
	"context"

	"github.com/xiongjiwei/mcp-ssh/session"
)

// AutoDenyApprover denies every request immediately.
// Used as the default provider and for unattended/headless scenarios.
type AutoDenyApprover struct{}

func (a *AutoDenyApprover) RequestApproval(_ context.Context, _ session.Request) (Decision, error) {
	return Decision{Allow: false}, nil
}
