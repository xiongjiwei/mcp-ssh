package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type Logger struct {
	logWriter  io.Writer
	eventSink  io.Writer
}

func New(logWriter io.Writer, jsonOut io.Writer) *Logger {
	return &Logger{logWriter: logWriter, eventSink: jsonOut}
}

func (l *Logger) LogExec(remoteIP, user, host, sessionID, command, stdout, digest string, exitCode int, durationMs int64) {
	ts := now()
	oneLine := strings.ReplaceAll(strings.TrimRight(stdout, "\n"), "\n", `\n`)
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] [digest:%s] EXEC: %s EXIT:%d duration:%dms OUT:%s\n", ts, remoteIP, user, host, sessionID, digest, command, exitCode, durationMs, oneLine))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s executed: `%s`", user, host, command),
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "exec", "command": command, "digest": digest,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogOpen(remoteIP, user, host, sessionID string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] OPEN\n", ts, remoteIP, user, host, sessionID))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s session opened", user, host),
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "open",
	})
}

func (l *Logger) LogClose(remoteIP, user, host, sessionID string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] CLOSE\n", ts, remoteIP, user, host, sessionID))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s session closed", user, host),
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "close",
	})
}

func (l *Logger) LogApprovalRequested(remoteIP, user, host, sessionID, command, digest string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] [digest:%s] APPROVAL: REQUESTED %s\n", ts, remoteIP, user, host, sessionID, digest, command))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s approval requested: `%s`", user, host, command),
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "approval_requested", "command": command, "digest": digest,
	})
}

func (l *Logger) LogApprovalDecision(remoteIP, user, host, sessionID, command, digest, reason string, allowed bool) {
	ts := now()
	outcome := "APPROVED"
	event := "approval_approved"
	msg := "approval approved"
	if !allowed {
		outcome = "DENIED"
		event = "approval_denied"
		msg = "approval denied"
	}
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] [digest:%s] APPROVAL: %s %s\n", ts, remoteIP, user, host, sessionID, digest, outcome, command))
	ev := map[string]any{
		"_msg": fmt.Sprintf("%s@%s %s: `%s`", user, host, msg, command),
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": event, "command": command, "digest": digest,
	}
	if reason != "" {
		ev["reason"] = reason
	}
	l.publishEvent(ev)
}

func (l *Logger) appendFile(line string) {
	l.logWriter.Write([]byte(line))
}

func (l *Logger) publishEvent(v any) {
	b, _ := json.Marshal(v)
	l.eventSink.Write(append(b, '\n'))
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// CmdDigest returns a short (4-byte hex) digest that correlates audit log
// entries for the same command: approval_requested, approval_approved/denied,
// and exec all share the same digest.
func CmdDigest(sessionID, command string) string {
	ts := now()
	return cmdDigest(sessionID, command, ts)
}

func cmdDigest(sessionID, command, ts string) string {
	h := sha256.Sum256([]byte(sessionID + command + ts))
	return fmt.Sprintf("%x", h[:16])
}
