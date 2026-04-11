package approval

import (
	"context"
	"log/slog"
	"time"
)

// Decision holds the outcome of an approval request.
type Decision struct {
	Allow  bool
	Reason string // human-readable explanation, may be empty
}

// Approver decides whether a command is allowed to execute.
type Approver interface {
	// RequestApproval returns a Decision and nil on success, or a zero Decision
	// and non-nil error on failure. Implementations must respect ctx.Done() and
	// return promptly on cancellation.
	// digest is the audit digest that correlates this request with its exec log entry.
	RequestApproval(ctx context.Context, user, host, remoteIP, command, digest string) (Decision, error)
}

// WebhookConfig holds webhook-specific settings (mirrors config.WebhookConfig
// without importing the config package).
type WebhookConfig struct {
	TimeoutSeconds int
	TimeoutAction  string // "allow" or anything else → deny
}

// Config holds configuration for creating approvers.
type Config struct {
	Provider  string
	Transport string // "stdio" or "serve"
	Webhook   WebhookConfig
}

// NewApprover returns the Approver for the given provider name.
// Unknown providers fall back to AutoDenyApprover.
func NewApprover(cfg Config) Approver {
	switch cfg.Provider {
	case "auto_allow":
		return &AutoAllowApprover{}
	case "webhook":
		timeout := time.Duration(cfg.Webhook.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 300 * time.Second
		}
		onTimeout := cfg.Webhook.TimeoutAction == "allow"
		if cfg.Transport == "stdio" {
			action := "denied"
			if onTimeout {
				action = "allowed"
			}
			slog.Warn("webhook approval provider has no effect in stdio mode",
				"non_whitelisted_commands_will_be", action)
		}
		return &WebhookApprover{
			pending:   make(map[string]*pendingRequest),
			notify:    make(chan struct{}),
			timeout:   timeout,
			onTimeout: onTimeout,
			transport: cfg.Transport,
		}
	default:
		return &AutoDenyApprover{}
	}
}
