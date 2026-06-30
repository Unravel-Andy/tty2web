//go:build !windows
// +build !windows

package localcommand

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"testing"
)

func TestIsPlainBashCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		argv    []string
		want    bool
	}{
		{name: "bash", command: "bash", want: true},
		{name: "bin bash", command: "/bin/bash", want: true},
		{name: "bash with args", command: "bash", argv: []string{"-c", "echo hi"}, want: false},
		{name: "sh", command: "sh", want: false},
		{name: "zsh", command: "zsh", want: false},
		{name: "k9s", command: "k9s", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPlainBashCommand(tt.command, tt.argv); got != tt.want {
				t.Fatalf("isPlainBashCommand(%q, %v) = %t, want %t", tt.command, tt.argv, got, tt.want)
			}
		})
	}
}

func TestBashAuditScriptEmitsMarker(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}

	auditFile, err := createBashAuditFile("bash", nil)
	if err != nil {
		t.Fatalf("createBashAuditFile() error = %v", err)
	}
	defer os.Remove(auditFile)

	output, err := exec.Command("bash", "--rcfile", auditFile, "-i", "-c", "echo hello").Output()
	if err != nil {
		t.Fatalf("bash audit command error = %v", err)
	}

	encodedCommand := base64.StdEncoding.EncodeToString([]byte("echo hello"))
	marker := []byte("\x1b]777;tty2web-audit=" + encodedCommand + "\x07")
	if !bytes.Contains(output, marker) {
		t.Fatalf("output does not contain audit marker for echo hello: %q", string(output))
	}
}
