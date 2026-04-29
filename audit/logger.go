package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xiongjiwei/mcp-ssh/session"
)

type Logger struct {
	logWriter io.Writer
	eventSink io.Writer
}

func New(logWriter io.Writer, jsonOut io.Writer) *Logger {
	return &Logger{logWriter: logWriter, eventSink: jsonOut}
}

func (l *Logger) LogExec(sessionID string, req session.Request, stdout string, exitCode int, durationMs int64) {
	ts := now()
	oneLine := strings.ReplaceAll(strings.TrimRight(stdout, "\n"), "\n", `\n`)
	l.appendFile(fmt.Sprintf("%s [session:%s] %s EXEC: %s EXIT:%d duration:%dms OUT:%s\n",
		ts, sessionID, req.LogLine(), req.Command, exitCode, durationMs, oneLine))
	ev := event(ts, sessionID, req)
	ev["_msg"] = fmt.Sprintf("%s@%s executed: `%s`", req.User, req.Host, req.Command)
	ev["event"] = "exec"
	ev["exit_code"] = exitCode
	ev["duration_ms"] = durationMs
	l.publishEvent(ev)
}

func (l *Logger) LogOpen(remoteIP, user, host, sessionID string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [session:%s] [%s] [%s@%s] OPEN\n", ts, sessionID, remoteIP, user, host))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s session opened", user, host),
		"time": ts, "session": sessionID, "remote_ip": remoteIP, "user": user, "host": host,
		"event": "open",
	})
}

func (l *Logger) LogClose(remoteIP, user, host, sessionID string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [session:%s] [%s] [%s@%s] CLOSE\n", ts, sessionID, remoteIP, user, host))
	l.publishEvent(map[string]any{
		"_msg": fmt.Sprintf("%s@%s session closed", user, host),
		"time": ts, "session": sessionID, "remote_ip": remoteIP, "user": user, "host": host,
		"event": "close",
	})
}

func (l *Logger) LogApprovalRequested(sessionID string, req session.Request) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [session:%s] %s APPROVAL: REQUESTED %s\n", ts, sessionID, req.LogLine(), req.Command))
	ev := event(ts, sessionID, req)
	ev["_msg"] = fmt.Sprintf("%s@%s approval requested: `%s`", req.User, req.Host, req.Command)
	ev["event"] = "approval_requested"
	l.publishEvent(ev)
}

func (l *Logger) LogApprovalDecision(sessionID string, req session.Request, reason string, allowed bool) {
	ts := now()
	outcome, eventName, msg := "APPROVED", "approval_approved", "approval approved"
	if !allowed {
		outcome, eventName, msg = "DENIED", "approval_denied", "approval denied"
	}
	l.appendFile(fmt.Sprintf("%s [session:%s] %s APPROVAL: %s %s [reason: %s]\n",
		ts, sessionID, req.LogLine(), outcome, req.Command, reason))
	ev := event(ts, sessionID, req)
	ev["_msg"] = fmt.Sprintf("%s@%s %s: `%s`; reason: %s", req.User, req.Host, msg, req.Command, reason)
	ev["event"] = eventName
	ev["reason"] = reason
	l.publishEvent(ev)
}

// event builds a JSON event map seeded with timestamp, session, and req fields.
func event(ts, sessionID string, req session.Request) map[string]any {
	ev := req.Fields()
	ev["time"] = ts
	ev["session"] = sessionID
	return ev
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

// CmdDigest returns a 16-byte (32 hex chars) digest that correlates audit log
// entries for the same command: approval_requested, approval_approved/denied,
// and exec all share the same digest.
func CmdDigest(sessionID, command string) string {
	h := sha256.Sum256([]byte(sessionID + command + now()))
	return fmt.Sprintf("%x", h[:16])
}
