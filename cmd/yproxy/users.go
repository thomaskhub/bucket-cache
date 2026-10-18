package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/users"
)

// stdin is where --password-stdin reads from; tests replace it.
var stdin io.Reader = os.Stdin

const userUsage = `Usage: yproxy user <command> [flags] NAME

Commands:
  create NAME           add a UI user (--admin for the admin role)
  reset-password NAME   set a new one-time password and unlock the account
  reset-totp NAME       remove the user's TOTP secret (lost phone); they enrol again
  list                  list users

Flags:
  --config PATH         config file (default $PROXY_CONFIG or /etc/proxy/config.yaml)
  --admin               create: give the user the admin role
  --password-file PATH  read the password from a file instead of generating one
  --password-stdin      read the password from the first line of stdin

Passwords are never taken from the command line. Without --password-file or
--password-stdin a one-time password is generated and printed. Either way the
user must set up TOTP and choose a new password at first login.
`

// setupUsers creates the users service for serve and bootstraps the
// initial admin from the secret files when there are no users (FR-64).
func setupUsers(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) (*users.Service, error) {
	var sealer *auth.Sealer
	if key := cfg.Auth.DBEncryptionKey.Value(); key != "" {
		s, err := auth.NewSealer(key)
		if err != nil {
			return nil, err
		}
		sealer = s
	} else {
		log.Warn("web UI login is disabled: set auth.db_encryption_key to enable users")
	}
	svc := users.New(st, sealer, log, users.Options{IdleTimeout: cfg.Auth.SessionIdleTimeout.D()})
	if sealer != nil {
		created, err := svc.Bootstrap(ctx, cfg.Auth.InitialAdminUser.Value(), cfg.Auth.InitialAdminPassword.Value())
		if err != nil {
			return nil, fmt.Errorf("creating the initial admin: %w", err)
		}
		if created {
			log.Info("created the initial admin from auth.initial_admin_user; it must set up TOTP and change the password at first login")
		}
	}
	return svc, nil
}

func userCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, userUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, userUsage) }
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	admin := fs.Bool("admin", false, "admin role")
	pwFile := fs.String("password-file", "", "read the password from this file")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	// Accept flags before and after NAME.
	var pos []string
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	switch sub {
	case "create", "reset-password", "reset-totp":
		if len(pos) != 1 {
			fmt.Fprint(stderr, userUsage)
			return 2
		}
	case "list":
		if len(pos) != 0 {
			fmt.Fprint(stderr, userUsage)
			return 2
		}
	default:
		fmt.Fprint(stderr, userUsage)
		return 2
	}
	if *pwFile != "" && *pwStdin {
		fmt.Fprintln(stderr, "use either --password-file or --password-stdin")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config %s is invalid:\n%v\n", *cfgPath, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "opening database %s: %v\n", cfg.Storage.DBPath, err)
		return 1
	}
	defer st.Close()
	// CLI actions are logged to stderr like the server's, without secrets.
	svc := users.New(st, nil, newLogger("warn", stderr), users.Options{})

	password := ""
	if sub == "create" || sub == "reset-password" {
		if password, err = readPassword(*pwFile, *pwStdin); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	switch sub {
	case "list":
		return listUsers(ctx, st, stdout, stderr)
	case "create":
		role := users.RoleUser
		if *admin {
			role = users.RoleAdmin
		}
		u, generated, err := svc.CreateUser(ctx, pos[0], role, password)
		if errors.Is(err, store.ErrConflict) {
			fmt.Fprintf(stderr, "user %s already exists\n", pos[0])
			return 1
		}
		if err != nil {
			fmt.Fprintf(stderr, "creating user: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "created user %s (%s, id %s)\n", u.Username, u.Role, u.ID)
		printOneTime(stdout, generated)
		return 0
	}

	u, err := svc.Lookup(ctx, pos[0])
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(stderr, "no user %s\n", pos[0])
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "looking up user: %v\n", err)
		return 1
	}
	switch sub {
	case "reset-password":
		generated, err := svc.ResetPassword(ctx, u.ID, password)
		if err != nil {
			fmt.Fprintf(stderr, "resetting password: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "reset the password of %s and unlocked the account; their sessions were ended\n", u.Username)
		printOneTime(stdout, generated)
	case "reset-totp":
		if err := svc.ResetTOTP(ctx, u.ID); err != nil {
			fmt.Fprintf(stderr, "resetting TOTP: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "removed the TOTP secret of %s and unlocked the account; they set up TOTP again at next login\n", u.Username)
	}
	return 0
}

func printOneTime(w io.Writer, pw string) {
	if pw == "" {
		fmt.Fprintln(w, "The user must set up TOTP and choose a new password at first login.")
		return
	}
	fmt.Fprintf(w, "one-time password: %s\nThe user must set up TOTP and choose a new password at first login.\n", pw)
}

// readPassword reads a password from a file or stdin; "" means generate one.
func readPassword(file string, fromStdin bool) (string, error) {
	var pw string
	switch {
	case file != "":
		b, err := os.ReadFile(file) //nolint:gosec // G703: a path the operator chose on the command line
		if err != nil {
			return "", fmt.Errorf("reading password file: %w", err)
		}
		pw = strings.TrimRight(string(b), "\r\n")
	case fromStdin:
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	default:
		return "", nil
	}
	if pw == "" {
		return "", errors.New("the password is empty")
	}
	if len(pw) < users.MinPasswordLength {
		return "", fmt.Errorf("the password must be at least %d characters", users.MinPasswordLength)
	}
	return pw, nil
}

func listUsers(ctx context.Context, st *store.Store, stdout, stderr io.Writer) int {
	list, err := st.ListUsers(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "listing users: %v\n", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSERNAME\tROLE\tTOTP\tSTATUS")
	now := time.Now()
	for _, u := range list {
		status := "active"
		switch {
		case u.Disabled():
			status = "disabled"
		case u.Locked(now):
			status = "locked"
		case u.MustChangePassword:
			status = "password change pending"
		}
		totp := "no"
		if u.TOTPEnrolled() {
			totp = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.ID, u.Username, u.Role, totp, status)
	}
	if err := tw.Flush(); err != nil {
		return 1
	}
	return 0
}
