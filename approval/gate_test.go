package approval_test

import (
	"context"
	"testing"

	"github.com/xiongjiwei/mcp-ssh/approval"
)

func gate(whitelist []string) *approval.Gate {
	return approval.NewGate(whitelist, approval.NewApprover(approval.Config{Provider: "auto_deny"}))
}

func TestGate_Whitelisted_NoApprovalNeeded(t *testing.T) {
	g := gate([]string{"ls", "grep", "cat"})
	dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", "ls -la /etc", "")
	if err != nil || !dec.Allow {
		t.Errorf("whitelisted command should pass: ok=%v err=%v", dec.Allow, err)
	}
}

func TestGate_PathNormalized(t *testing.T) {
	g := gate([]string{"ls"})
	dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", "/bin/ls -la", "")
	if err != nil || !dec.Allow {
		t.Errorf("/bin/ls should normalize to ls: ok=%v err=%v", dec.Allow, err)
	}
}

func TestGate_NotWhitelisted_AutoDeny(t *testing.T) {
	g := gate([]string{"ls"})
	dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", "rm -rf /data", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Allow {
		t.Error("rm should be denied by AutoDenyApprover")
	}
}

func TestGate_CompoundAllWhitelisted(t *testing.T) {
	g := gate([]string{"ls", "grep"})
	dec, _ := g.Check(context.Background(), "alice", "srv1", "", "s1", "ls /tmp | grep foo", "")
	if !dec.Allow {
		t.Error("both tokens whitelisted, should pass")
	}
}

func TestGate_CompoundOneNotWhitelisted(t *testing.T) {
	g := gate([]string{"ls"})
	dec, _ := g.Check(context.Background(), "alice", "srv1", "", "s1", "ls /tmp && rm -rf /", "")
	if dec.Allow {
		t.Error("rm not whitelisted, should deny")
	}
}

func TestGate_AmbiguousPattern_Deny(t *testing.T) {
	g := gate([]string{"ls", "echo"})
	cases := []string{
		"echo $(ls)",
		"ls `pwd`",
		"{ ls; echo done; }",
	}
	for _, c := range cases {
		dec, _ := g.Check(context.Background(), "alice", "srv1", "", "s1", c, "")
		if dec.Allow {
			t.Errorf("ambiguous command should require approval (denied by auto_deny): %q", c)
		}
	}
}

func TestGate_DefaultWhitelist(t *testing.T) {
	g := gate([]string{
		"ls", "pwd", "cat", "echo", "grep", "find", "wc",
		"head", "tail", "ps", "df", "du", "uname",
		"whoami", "env", "cd",
	})

	tests := []struct {
		command string
		want    bool
	}{
		// Basic whitelisted commands
		{"ls -la", true},
		{"pwd", true},
		{"cat /etc/hosts", true},
		{"echo hello world", true},
		{"grep pattern file.txt", true},
		{"find /tmp -name '*.log'", true},
		{"wc -l file.txt", true},
		{"head -n 10 file.txt", true},
		{"tail -f /var/log/syslog", true},
		{"ps aux", true},
		{"df -h", true},
		{"du -sh /home", true},
		{"uname -a", true},
		{"whoami", true},
		{"env", true},
		{"cd /tmp", true},
		// Path variants should also work
		{"/bin/ls", true},
		{"/usr/bin/grep pattern", true},
		// Ambiguous command
		{"grep -E \"cmd:(create|stat)\" 1.log | head -20", true},
		// Not whitelisted
		{"rm -rf /", false},
		{"sudo reboot", false},
		{"chmod 777 /etc/passwd", false},
		{"curl http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}

func TestGate_QuotedCommands(t *testing.T) {
	g := gate([]string{"ls", "grep", "echo", "cat", "head"})

	tests := []struct {
		command string
		want    bool
	}{
		// Regex with pipe inside double quotes
		{`grep -E "a|b" file.txt`, true},
		{`grep -E "cmd:(create|stat)" 1.log | head -20`, true},
		{`grep -E 'a|b' file.txt`, true},
		// Semicolon inside quotes should not split
		{`echo "hello; world"`, true},
		{`echo 'hello; world'`, true},
		// Ampersand inside quotes should not split
		{`echo "foo && bar"`, true},
		{`echo 'foo && bar'`, true},
		// Pipe inside quotes should not split
		{`echo "a | b"`, true},
		{`echo 'a | b'`, true},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}

func TestGate_CompoundCommands(t *testing.T) {
	g := gate([]string{"ls", "grep", "cat", "echo", "head", "tail", "wc"})

	tests := []struct {
		command string
		want    bool
	}{
		// Pipe chains - all whitelisted
		{"ls | grep foo", true},
		{"ls | grep foo | head -10", true},
		{"cat file.txt | grep pattern | wc -l", true},
		{"tail -f log | grep error", true},
		// && chains - all whitelisted
		{"ls /tmp && grep foo file.txt", true},
		{"cat a.txt && cat b.txt && cat c.txt", true},
		// || chains - all whitelisted
		{"ls /tmp || echo not found", true},
		// Semicolon chains - all whitelisted
		{"ls; grep foo", true},
		// Mixed operators
		{"ls | grep foo && echo found", true},
		{"cat file | grep pattern || echo not found", true},
		// One command not whitelisted
		{"ls | grep foo | rm -rf /", false},
		{"ls && rm -rf /", false},
		{"rm -rf / || ls", false},
		{"cat file; rm file", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}

func TestGate_EdgeCases(t *testing.T) {
	g := gate([]string{"ls", "echo", "grep"})

	tests := []struct {
		command string
		want    bool
	}{
		// Empty and whitespace
		{"", false},
		// Note: "   " returns true because splitCompound returns empty slice
		// which is handled as no command to check
		// Multiple spaces between args
		{"ls    -la   /tmp", true},
		// Leading/trailing whitespace
		{"   ls -la   ", true},
		// Path normalization
		{"/bin/ls", true},
		{"/usr/bin/ls", true},
		{"../../bin/ls", true},
		// Complex grep patterns
		{`grep -E "^[0-9]+"`, true},
		{`grep -i "ERROR|WARN" log.txt`, true},
		{`grep -v '^#' config.conf`, true},
		// Echo with special chars
		{"echo 'Hello, World!'", true},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}

func TestGate_AmbiguousPatterns(t *testing.T) {
	g := gate([]string{"ls", "echo", "grep", "cat"})

	tests := []struct {
		command string
		want    bool
	}{
		// Command substitution - should deny
		{"echo $(ls)", false},
		{"ls `pwd`", false},
		{"cat $(find /tmp -name '*.log')", false},
		// Brace expansion - should deny
		{"{ ls; echo done; }", false},
		// Backticks in different contexts
		{"echo `hostname`", false},
		// Note: backtick inside single quotes is still detected by containsAmbiguous
		// because it checks the raw string before quote parsing
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}

func TestGate_ComplexShellConstructs(t *testing.T) {
	g := gate([]string{"ls", "echo", "grep", "cat", "mv", "for"})

	tests := []struct {
		command string
		want    bool
	}{
		// For loop with brace - should deny due to { in pattern
		{`for f in *.txt; do mv "$f" "${f%.txt}_spark.txt"; done`, false},
		// Brace expansion variants
		{`echo {a,b,c}`, false},
		{`cat file{1,2,3}.txt`, false},
		// Subshell
		{`(cd /tmp && ls)`, false},
		// Process substitution
		{`grep pattern <(cat file.txt)`, false},
		{`echo >(cat)`, false},
		// Array expansion with braces
		{`echo ${arr[0]}`, false},
		{`echo ${var:-default}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			dec, err := g.Check(context.Background(), "alice", "srv1", "", "s1", tt.command, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Allow != tt.want {
				t.Errorf("command %q: got ok=%v, want %v", tt.command, dec.Allow, tt.want)
			}
		})
	}
}
