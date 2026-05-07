package session

import "fmt"

// Request holds the context for a single command execution on a remote host.
type Request struct {
	User        string
	Host        string
	RemoteIP    string
	Command     string
	Description string // caller-provided summary of the command's purpose
	Cwd         string // verified from the remote session via pwd
	Digest      string // correlates with the audit log entry
}

// LogLine returns the formatted fragment used in text audit log lines.
func (r Request) LogLine() string {
	s := fmt.Sprintf("[%s] [%s@%s]", r.RemoteIP, r.User, r.Host)
	if r.Digest != "" {
		s += fmt.Sprintf(" [digest:%s]", r.Digest)
	}
	if r.Cwd != "" {
		s += fmt.Sprintf(" [cwd:%s]", r.Cwd)
	}
	if r.Description != "" {
		s += fmt.Sprintf(" [desc:%s]", r.Description)
	}
	return s
}

// Fields returns the common JSON event fields for this request.
func (r Request) Fields() map[string]any {
	return map[string]any{
		"remote_ip":   r.RemoteIP,
		"user":        r.User,
		"host":        r.Host,
		"command":     r.Command,
		"description": r.Description,
		"digest":      r.Digest,
		"cwd":         r.Cwd,
	}
}
