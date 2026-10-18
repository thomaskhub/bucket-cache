//go:build !unix

package gitmirror

import "os/exec"

// setProcGroup is a no-op where process groups don't exist; cancelling the
// context still kills git itself.
func setProcGroup(*exec.Cmd) {}
