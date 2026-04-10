package approval

import "context"

// AutoDenyApprover denies every request immediately.
// Used as the default provider and for unattended/headless scenarios.
type AutoDenyApprover struct{}

func (a *AutoDenyApprover) RequestApproval(_ context.Context, _, _, _, _ string) (bool, error) {
	return false, nil
}
