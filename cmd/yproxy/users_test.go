package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

func init() { auth.PasswordParams = auth.Argon2Params{Memory: 64, Time: 1, Threads: 1} }

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func userConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "p.db")
	cfgPath = writeFile(t, dir, "c.yaml", "storage:\n  db_path: "+dbPath+"\n")
	return cfgPath, dbPath
}

func runUser(t *testing.T, in string, args ...string) (int, string, string) {
	t.Helper()
	stdin = strings.NewReader(in)
	defer func() { stdin = os.Stdin }()
	var out, errb bytes.Buffer
	code := run(append([]string{"user"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func userByName(t *testing.T, dbPath, name string) *store.User {
	t.Helper()
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UserByName(context.Background(), name)
	if err != nil {
		t.Fatalf("user %s: %v", name, err)
	}
	return u
}

func TestUserCLI(t *testing.T) {
	cfg, db := userConfig(t)

	// Generated one-time password.
	code, out, errOut := runUser(t, "", "create", "dev", "--config", cfg)
	if code != 0 {
		t.Fatalf("create: %d %s", code, errOut)
	}
	m := regexp.MustCompile(`one-time password: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no one-time password in %q", out)
	}
	u := userByName(t, db, "dev")
	if u.Role != "user" || !u.MustChangePassword || auth.VerifyPassword(u.PasswordHash, m[1]) != nil {
		t.Fatalf("dev = %+v", u)
	}

	// Admin with the password from stdin; it is not echoed.
	code, out, errOut = runUser(t, "stdin-password-123\n", "create", "--config", cfg, "--admin", "--password-stdin", "boss")
	if code != 0 || strings.Contains(out, "stdin-password-123") || strings.Contains(errOut, "stdin-password-123") {
		t.Fatalf("create --admin: %d %q %q", code, out, errOut)
	}
	if u := userByName(t, db, "boss"); u.Role != "admin" || auth.VerifyPassword(u.PasswordHash, "stdin-password-123") != nil {
		t.Fatalf("boss = %+v", u)
	}
	if code, _, errOut := runUser(t, "", "create", "--config", cfg, "BOSS"); code != 1 || !strings.Contains(errOut, "already exists") {
		t.Fatalf("duplicate: %d %s", code, errOut)
	}
	// Passwords can't be given on the command line.
	if code, _, _ := runUser(t, "", "create", "--config", cfg, "--password", "x", "eve"); code != 2 {
		t.Fatalf("--password accepted: %d", code)
	}
	if code, _, errOut := runUser(t, "short\n", "create", "--config", cfg, "--password-stdin", "eve"); code != 1 || !strings.Contains(errOut, "at least") {
		t.Fatalf("short password: %d %s", code, errOut)
	}

	// reset-password from a file; also unlocks.
	st, _ := store.Open(context.Background(), db)
	for i := 0; i < 5; i++ {
		st.RecordLoginFailure(context.Background(), u.ID, 5, u.CreatedAt.Add(1e15))
	}
	st.Close()
	pwFile := writeFile(t, t.TempDir(), "pw", "file-password-1234\n")
	if code, out, errOut := runUser(t, "", "reset-password", "dev", "--config", cfg, "--password-file", pwFile); code != 0 || strings.Contains(out, "file-password") {
		t.Fatalf("reset-password: %d %q %s", code, out, errOut)
	}
	u = userByName(t, db, "dev")
	if auth.VerifyPassword(u.PasswordHash, "file-password-1234") != nil || u.FailedLogins != 0 || u.LockedUntil != nil || !u.MustChangePassword {
		t.Fatalf("after reset-password: %+v", u)
	}

	// reset-totp by name or ID.
	st, _ = store.Open(context.Background(), db)
	st.SetPendingTOTP(context.Background(), u.ID, "v1:x")
	st.ActivateTOTP(context.Background(), u.ID, 5)
	st.Close()
	if code, _, errOut := runUser(t, "", "reset-totp", "--config", cfg, u.ID); code != 0 {
		t.Fatalf("reset-totp: %d %s", code, errOut)
	}
	if u := userByName(t, db, "dev"); u.TOTPEnrolled() {
		t.Fatal("TOTP not reset")
	}
	if code, _, _ := runUser(t, "", "reset-totp", "--config", cfg, "nobody"); code != 1 {
		t.Fatalf("unknown user: %d", code)
	}

	code, out, _ = runUser(t, "", "list", "--config", cfg)
	if code != 0 || !strings.Contains(out, "boss") || !strings.Contains(out, "dev") || strings.Contains(out, "argon2") {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, _, _ := runUser(t, ""); code != 2 {
		t.Fatalf("no subcommand: %d", code)
	}
}

// FR-64: on first start the admin is created from the secret files, and
// only while the user table is empty.
func TestSetupUsersBootstrap(t *testing.T) {
	dir := t.TempDir()
	yml := "storage:\n  db_path: " + filepath.Join(dir, "p.db") + "\nauth:\n" +
		"  initial_admin_user: { file: " + writeFile(t, dir, "u", "root\n") + " }\n" +
		"  initial_admin_password: { file: " + writeFile(t, dir, "p", "bootstrap-pass-12\n") + " }\n" +
		"  db_encryption_key: { file: " + writeFile(t, dir, "k", "a-long-enough-master-key\n") + " }\n"
	cfg, err := config.Parse([]byte(yml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), cfg.Storage.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	svc, err := setupUsers(context.Background(), cfg, st, log)
	if err != nil || !svc.LoginEnabled() {
		t.Fatalf("setupUsers: %v", err)
	}
	u, err := st.UserByName(context.Background(), "root")
	if err != nil || u.Role != "admin" || !u.MustChangePassword || u.TOTPEnrolled() {
		t.Fatalf("bootstrap admin = %+v, %v", u, err)
	}
	if strings.Contains(logs.String(), "bootstrap-pass-12") || strings.Contains(logs.String(), "a-long-enough-master-key") {
		t.Fatal("secret in log")
	}
	// A restart doesn't touch existing users (e.g. after a password change).
	st.SetPassword(context.Background(), u.ID, "changed", false)
	if _, err := setupUsers(context.Background(), cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if u, _ := st.UserByName(context.Background(), "root"); u.PasswordHash != "changed" {
		t.Fatal("bootstrap overwrote the admin")
	}

	// Without db_encryption_key the config is rejected when initial admin is set.
	bad := "auth:\n  initial_admin_user: { file: /x }\n  initial_admin_password: { file: /y }\n"
	if _, err := config.Parse([]byte(bad), func(string) (string, bool) { return "", false }); err == nil || !strings.Contains(err.Error(), "db_encryption_key") {
		t.Fatalf("config without db_encryption_key: %v", err)
	}
}
