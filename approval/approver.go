package approval

import (
	"context"
	"log/slog"
	"time"
)

// Approver decides whether a command is allowed to execute.
type Approver interface {
	// RequestApproval returns (true, nil) to allow, (false, nil) to deny,
	// or (false, err) if the approval mechanism itself failed.
	// Implementations must respect ctx.Done() and return promptly on cancellation.
	RequestApproval(ctx context.Context, user, host, remoteIP, command string) (bool, error)
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
