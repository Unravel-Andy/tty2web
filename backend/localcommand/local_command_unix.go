//go:build !windows
// +build !windows

package localcommand

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/pkg/errors"
)

const (
	DefaultCloseSignal  = syscall.SIGINT
	DefaultCloseTimeout = 10 * time.Second
)

type LocalCommand struct {
	command string
	argv    []string

	closeSignal  syscall.Signal
	closeTimeout time.Duration

	cmd       *exec.Cmd
	pty       pty.Pty
	ptyClosed chan struct{}
	auditFile string
}

func New(command string, argv []string, options ...Option) (*LocalCommand, error) {
	auditFile, err := createBashAuditFile(command, argv)
	if err != nil {
		return nil, err
	}
	if auditFile != "" {
		argv = append([]string{"--rcfile", auditFile, "-i"}, argv...)
	}

	cmd := exec.Command(command, argv...)

	pty, err := pty.Start(cmd)
	if err != nil {
		if auditFile != "" {
			os.Remove(auditFile)
		}
		// todo close cmd?
		return nil, errors.Wrapf(err, "failed to start command `%s`", command)
	}
	ptyClosed := make(chan struct{})

	lcmd := &LocalCommand{
		command: command,
		argv:    argv,

		closeSignal:  DefaultCloseSignal,
		closeTimeout: DefaultCloseTimeout,

		cmd:       cmd,
		pty:       pty,
		ptyClosed: ptyClosed,
		auditFile: auditFile,
	}

	for _, option := range options {
		option(lcmd)
	}

	// When the process is closed by the user,
	// close pty so that Read() on the pty breaks with an EOF.
	go func() {
		defer func() {
			lcmd.pty.Close()
			if lcmd.auditFile != "" {
				os.Remove(lcmd.auditFile)
			}
			close(lcmd.ptyClosed)
		}()

		lcmd.cmd.Wait()
	}()

	return lcmd, nil
}

func createBashAuditFile(command string, argv []string) (string, error) {
	if !isPlainBashCommand(command, argv) {
		return "", nil
	}

	file, err := os.CreateTemp("", "tty2web-bashrc-*")
	if err != nil {
		return "", errors.Wrap(err, "failed to create bash audit rcfile")
	}
	defer file.Close()

	if _, err := file.WriteString(bashAuditScript()); err != nil {
		os.Remove(file.Name())
		return "", errors.Wrap(err, "failed to write bash audit rcfile")
	}

	log.Printf("Bash command audit hook enabled")
	return file.Name(), nil
}

func isPlainBashCommand(command string, argv []string) bool {
	base := filepath.Base(command)
	if base != "bash" {
		log.Printf("Bash command audit hook disabled for non-bash command %q", command)
		return false
	}
	if len(argv) > 0 {
		log.Printf("Bash command audit hook disabled for bash with arguments")
		return false
	}
	return true
}

func bashAuditScript() string {
	return `if [ -f ~/.bashrc ]; then
	. ~/.bashrc
fi

__tty2web_audit_debug() {
	local command=$BASH_COMMAND
	case "$command" in
		__tty2web_audit_debug*|trap\ *|PROMPT_COMMAND=*)
			return 0
			;;
	esac
	if [ -n "$command" ]; then
		printf '\033]777;tty2web-audit=%s\a' "$(printf '%s' "$command" | base64 | tr -d '\n')"
	fi
}

trap '__tty2web_audit_debug' DEBUG
`
}

func (lcmd *LocalCommand) Read(p []byte) (n int, err error) {
	return lcmd.pty.Read(p)
}

func (lcmd *LocalCommand) Write(p []byte) (n int, err error) {
	return lcmd.pty.Write(p)
}

func (lcmd *LocalCommand) Close() error {
	if lcmd.cmd != nil && lcmd.cmd.Process != nil {
		lcmd.cmd.Process.Signal(lcmd.closeSignal)
	}
	for {
		select {
		case <-lcmd.ptyClosed:
			return nil
		case <-lcmd.closeTimeoutC():
			lcmd.cmd.Process.Signal(syscall.SIGKILL)
		}
	}
}

func (lcmd *LocalCommand) WindowTitleVariables() map[string]interface{} {
	return map[string]interface{}{
		"command": lcmd.command,
		"argv":    lcmd.argv,
		"pid":     lcmd.cmd.Process.Pid,
	}
}

func (lcmd *LocalCommand) ResizeTerminal(width int, height int) error {
	window := struct {
		row uint16
		col uint16
		x   uint16
		y   uint16
	}{
		uint16(height),
		uint16(width),
		0,
		0,
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		lcmd.pty.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&window)),
	)
	if errno != 0 {
		return errno
	} else {
		return nil
	}
}

func (lcmd *LocalCommand) closeTimeoutC() <-chan time.Time {
	if lcmd.closeTimeout >= 0 {
		return time.After(lcmd.closeTimeout)
	}

	return make(chan time.Time)
}
