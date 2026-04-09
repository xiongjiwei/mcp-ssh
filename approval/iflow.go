package approval

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// iFlowApprover sends approval requests to the iFlow platform
// and waits for human approval decisions.
type iFlowApprover struct {
	client     *http.Client
	endpoint   string
	apiKey     string
	pollPeriod time.Duration
}

// iFlowConfig holds configuration for the iFlow approver.
type iFlowConfig struct {
	Endpoint   string
	APIKey     string
	PollPeriod int
}

// NewiFlowApprover creates an approver that integrates with iFlow platform.
func NewiFlowApprover(cfg iFlowConfig) *iFlowApprover {
	pollPeriod := time.Duration(cfg.PollPeriod) * time.Second
	if pollPeriod <= 0 {
		pollPeriod = 5 * time.Second
	}
	return &iFlowApprover{
		client:     &http.Client{Timeout: 30 * time.Second},
		endpoint:   cfg.Endpoint,
		apiKey:     cfg.APIKey,
		pollPeriod: pollPeriod,
	}
}

// RequestApproval sends a request to iFlow and polls for the approval decision.
// It respects context cancellation for graceful shutdown.
func (a *iFlowApprover) RequestApproval(ctx context.Context, user, host, command string) (bool, error) {
	// TODO: Implement iFlow integration
	// 1. Create approval request via POST to iFlow API
	// 2. Poll for approval status until approved/denied or ctx cancelled
	// 3. Return the decision

	// Placeholder implementation - deny by default until iFlow is integrated
	return false, fmt.Errorf("iFlow approver not yet implemented: user=%s host=%s command=%s", user, host, command)
}