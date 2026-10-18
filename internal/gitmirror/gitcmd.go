package gitmirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// minGitVersion is the oldest git that has everything the mirror relies on:
// GIT_CONFIG_GLOBAL (2.32), protocol v2 with filters and ls-refs hideRefs.
var minGitVersion = [2]int{2, 32}

// passEnv lists the parent environment variables git subprocesses inherit.
// Everything else (including GIT_* from the parent) is dropped so the
// operator's shell can't change how the mirror behaves.
var passEnv = []string{
	"PATH", "LANG", "LC_ALL", "TZ",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
}

// runner starts git subprocesses with a fixed, minimal environment (FR-93):
// a writable HOME and TMPDIR under git.storage, no system or global config,
// no terminal prompts, and only http(s) as a transport.
type runner struct {
	git  string
	home string
	tmp  string
	env  []string

	// onExec, if set, sees the argv of every command (tests check that no
	// credential ever shows up there).
	onExec func(args []string)

	secretsMu sync.RWMutex
	secrets   map[string]struct{} // values redacted from error messages
}

func newRunner(gitBin, storage string) (*runner, error) {
	if gitBin == "" {
		gitBin = "git"
	}
	p, err := exec.LookPath(gitBin)
	if err != nil {
		return nil, fmt.Errorf("git binary not found: %w", err)
	}
	r := &runner{git: p, home: filepath.Join(storage, ".home"), tmp: filepath.Join(storage, ".tmp"), secrets: map[string]struct{}{}}
	for _, d := range []string{r.home, r.tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			r.env = append(r.env, k+"="+v)
		}
	}
	r.env = append(r.env,
		"HOME="+r.home,
		"TMPDIR="+r.tmp,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=http:https",
		"GIT_NO_REPLACE_OBJECTS=1",
	)
	return r, nil
}

// version returns git's major and minor version.
func (r *runner) version(ctx context.Context) ([2]int, string, error) {
	out, err := r.output(ctx, "", nil, nil, "version")
	if err != nil {
		return [2]int{}, "", err
	}
	s := strings.TrimSpace(string(out))
	m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(s)
	if m == nil {
		return [2]int{}, s, fmt.Errorf("unrecognised git version %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return [2]int{maj, minor}, s, nil
}

// addSecret registers a value that must never appear in error messages.
func (r *runner) addSecret(v string) {
	if v == "" {
		return
	}
	r.secretsMu.Lock()
	r.secrets[v] = struct{}{}
	r.secretsMu.Unlock()
}

// removeSecret forgets a value that is no longer in use (an expired
// GitHub App installation token).
func (r *runner) removeSecret(v string) {
	r.secretsMu.Lock()
	delete(r.secrets, v)
	r.secretsMu.Unlock()
}

func (r *runner) redact(s string) string {
	r.secretsMu.RLock()
	defer r.secretsMu.RUnlock()
	for v := range r.secrets {
		s = strings.ReplaceAll(s, v, "<redacted>")
	}
	return s
}

// command builds a git command. extraEnv carries per-call settings, such as
// GIT_PROTOCOL or upstream credentials as GIT_CONFIG_* (never argv).
func (r *runner) command(ctx context.Context, dir string, extraEnv []string, args ...string) *exec.Cmd {
	if r.onExec != nil {
		r.onExec(append([]string{r.git}, args...))
	}
	cmd := exec.CommandContext(ctx, r.git, args...) //nolint:gosec // G204: args are built by the proxy from validated names
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, r.env...), extraEnv...)
	setProcGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// GitError is a failed git command with the tail of its stderr (redacted).
type GitError struct {
	Args   string
	Err    error
	Stderr string
}

func (e *GitError) Error() string {
	msg := "git " + e.Args + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *GitError) Unwrap() error { return e.Err }

// output runs a command and returns its stdout.
func (r *runner) output(ctx context.Context, dir string, extraEnv []string, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := r.command(ctx, dir, extraEnv, args...)
	var stdout bytes.Buffer
	stderr := &tailBuffer{max: 4096}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), r.wrapErr(ctx, args, err, stderr)
	}
	return stdout.Bytes(), nil
}

func (r *runner) wrapErr(ctx context.Context, args []string, err error, stderr *tailBuffer) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	return &GitError{Args: name, Err: err, Stderr: r.redact(strings.TrimSpace(stderr.String()))}
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// isTimeout reports whether err came from a deadline.
func isTimeout(err error) bool { return errors.Is(err, context.DeadlineExceeded) }
