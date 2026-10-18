//go:build unix

package gitmirror

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts git in its own process group, so cancelling the context
// (client gone, timeout) also kills helpers such as git-remote-https and
// pack-objects instead of leaving them running.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
