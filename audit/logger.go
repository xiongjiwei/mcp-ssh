package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Logger struct {
	logPath string
	jsonOut io.Writer
}

func New(logPath string, jsonOut io.Writer) *Logger {
	return &Logger{logPath: logPath, jsonOut: jsonOut}
}

func (l *Logger) LogExec(host, sessionID, command, stdout string, exitCode int, durationMs int64) {
	ts := now()
	oneLine := strings.ReplaceAll(strings.TrimRight(stdout, "\n"), "\n", `\n`)
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] CMD: %s\n", ts, host, sessionID, command))
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] OUT: %s\n", ts, host, sessionID, oneLine))
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] EXIT: %d duration:%dms\n", ts, host, sessionID, exitCode, durationMs))
	l.writeJSON(map[string]any{
		"time": ts, "host": host, "session": sessionID,
		"event": "exec", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalRequested(host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] APPROVAL: REQUESTED %s\n", ts, host, sessionID, command))
	l.writeJSON(map[string]any{
		"time": ts, "host": host, "session": sessionID,
		"event": "approval_requested", "command": command,
	})
}

func (l *Logger) LogApprovalApproved(host, sessionID, command string, exitCode int, durationMs int64) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] APPROVAL: APPROVED %s\n", ts, host, sessionID, command))
	l.writeJSON(map[string]any{
		"time": ts, "host": host, "session": sessionID,
		"event": "approval_approved", "command": command,
		"exit_code": exitCode, "duration_ms": durationMs,
	})
}

func (l *Logger) LogApprovalDenied(host, sessionID, command string) {
	ts := now()
	l.appendFile(fmt.Sprintf("%s [%s] [session:%s] APPROVAL: DENIED by user\n", ts, host, sessionID))
	l.writeJSON(map[string]any{
		"time": ts, "host": host, "session": sessionID,
		"event": "approval_denied", "command": command,
	})
}

func (l *Logger) appendFile(line string) {
	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

func (l *Logger) writeJSON(v any) {
	b, _ := json.Marshal(v)
	l.jsonOut.Write(append(b, '\n'))
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
