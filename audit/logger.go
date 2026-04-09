package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type Logger struct {
	logWriter io.Writer
	jsonOut   io.Writer
}

func New(logWriter io.Writer, jsonOut io.Writer) *Logger {
	return &Logger{logWriter: logWriter, jsonOut: jsonOut}
}

func (l *Logger) LogExec(user, host, sessionID, command, stdout string, exitCode int, durationMs int64) {
	ts := now()
	oneLine := strings.ReplaceAll(strings.TrimRight(stdout, "\n"), "\n", `\n`)
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] CMD: %s\n", ts, user, host, sessionID, command))
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] OUT: %s\n", ts, user, host, sessionID, oneLine))
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] EXIT: %d duration:%dms\n", ts, user, host, sessionID, exitCode, durationMs))
	l.writeJSON(map[string]any{
		"time": ts, "user": user, "host": host, "session": sessionID,
		"event": "exec", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalRequested(user, host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] APPROVAL: REQUESTED %s\n", ts, user, host, sessionID, command))
	l.writeJSON(map[string]any{
		"time": ts, "user": user, "host": host, "session": sessionID,
		"event": "approval_requested", "command": command,
	})
}

func (l *Logger) LogApprovalApproved(user, host, sessionID, command string, exitCode int, durationMs int64) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] APPROVAL: APPROVED %s\n", ts, user, host, sessionID, command))
	l.writeJSON(map[string]any{
		"time": ts, "user": user, "host": host, "session": sessionID,
		"event": "approval_approved", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalDenied(user, host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s@%s] [session:%s] APPROVAL: DENIED by user\n", ts, user, host, sessionID))
	l.writeJSON(map[string]any{
		"time": ts, "user": user, "host": host, "session": sessionID,
		"event": "approval_denied", "command": command,
	})
}

func (l *Logger) appendFile(line string) {
	l.logWriter.Write([]byte(line))
}

func (l *Logger) writeJSON(v any) {
	b, _ := json.Marshal(v)
	l.jsonOut.Write(append(b, '\n'))
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
