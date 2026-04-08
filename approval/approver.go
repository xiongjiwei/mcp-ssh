package approval

import "context"

// Approver decides whether a command is allowed to execute.
type Approver interface {
	// RequestApproval returns (true, nil) to allow, (false, nil) to deny,
	// or (false, err) if the approval mechanism itself failed.
	// Implementations must respect ctx.Done() and return promptly on cancellation.
	RequestApproval(ctx context.Context, user, host, command string) (bool, error)
}

// NewApprover returns the Approver for the given provider name.
// Unknown providers fall back to AutoDenyApprover.
func NewApprover(provider string) Approver {
	switch provider {
	case "auto_deny":
		return &AutoDenyApprover{}
	default:
		return &AutoDenyApprover{}
	}
}
