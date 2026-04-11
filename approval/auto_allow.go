package approval

import "context"

// AutoAllowApprover approves every request immediately.
// Use only in trusted environments where unrestricted command execution is acceptable.
type AutoAllowApprover struct{}

func (a *AutoAllowApprover) RequestApproval(_ context.Context, _, _, _, _, _ string) (Decision, error) {
	return Decision{Allow: true}, nil
}
