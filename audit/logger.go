package audit

import (
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

func (l *Logger) LogExec(remoteIP, user, host, sessionID, command, stdout string, exitCode int, durationMs int64) {
	ts := now()
	oneLine := strings.ReplaceAll(strings.TrimRight(stdout, "\n"), "\n", `\n`)
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] EXEC: %s EXIT:%d duration:%dms OUT:%s\n", ts, remoteIP, user, host, sessionID, command, exitCode, durationMs, oneLine))
	l.publishEvent(map[string]any{
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "exec", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalRequested(remoteIP, user, host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] APPROVAL: REQUESTED %s\n", ts, remoteIP, user, host, sessionID, command))
	l.publishEvent(map[string]any{
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "approval_requested", "command": command,
	})
}

func (l *Logger) LogApprovalApproved(remoteIP, user, host, sessionID, command string, exitCode int, durationMs int64) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] APPROVAL: APPROVED %s\n", ts, remoteIP, user, host, sessionID, command))
	l.publishEvent(map[string]any{
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "approval_approved", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalDenied(remoteIP, user, host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [%s@%s] [session:%s] APPROVAL: DENIED by user\n", ts, remoteIP, user, host, sessionID))
	l.publishEvent(map[string]any{
		"time": ts, "remote_ip": remoteIP, "user": user, "host": host, "session": sessionID,
		"event": "approval_denied", "command": command,
	})
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
