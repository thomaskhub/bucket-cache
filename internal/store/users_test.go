package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	u := &User{ID: "usr_1", Username: "Alice", Role: "admin", PasswordHash: "h", MustChangePassword: true, CreatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &User{ID: "usr_2", Username: "alice", Role: "user", PasswordHash: "h", CreatedAt: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username (other case) = %v", err)
	}
	got, err := s.UserByName(ctx, "ALICE")
	if err != nil || got.ID != "usr_1" || !got.MustChangePassword || got.TOTPEnrolled() || got.Disabled() {
		t.Fatalf("UserByName = %+v, %v", got, err)
	}
	if _, err := s.UserByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user = %v", err)
	}

	// TOTP: pending, activate, replay-protected steps, reset.
	if err := s.SetPendingTOTP(ctx, "usr_1", "v1:sealed"); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateTOTP(ctx, "usr_1", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateTOTP(ctx, "usr_1", 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activate without pending = %v", err)
	}
	got, _ = s.UserByID(ctx, "usr_1")
	if got.TOTPSecret != "v1:sealed" || got.TOTPPending != "" || got.TOTPLastStep != 100 {
		t.Fatalf("after activate: %+v", got)
	}
	for _, c := range []struct {
		step int64
		ok   bool
	}{{100, false}, {99, false}, {101, true}, {101, false}} {
		ok, err := s.UseTOTPStep(ctx, "usr_1", c.step)
		if err != nil || ok != c.ok {
			t.Errorf("UseTOTPStep(%d) = %v, %v; want %v", c.step, ok, err, c.ok)
		}
	}

	// Lockout after 3 failures, cleared by success.
	for i := 1; i <= 3; i++ {
		n, err := s.RecordLoginFailure(ctx, "usr_1", 3, now.Add(15*time.Minute))
		if err != nil || n != i {
			t.Fatalf("failure %d: n=%d err=%v", i, n, err)
		}
		got, _ = s.UserByID(ctx, "usr_1")
		if got.Locked(now) != (i == 3) {
			t.Fatalf("after %d failures locked=%v", i, got.Locked(now))
		}
	}
	if got.Locked(now.Add(16 * time.Minute)) {
		t.Fatal("lock did not expire")
	}
	if err := s.RecordLoginSuccess(ctx, "usr_1", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(ctx, "usr_1")
	if got.FailedLogins != 0 || got.LockedUntil != nil || got.LastLoginAt == nil {
		t.Fatalf("after success: %+v", got)
	}

	if err := s.ResetTOTP(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, "usr_1", "h2", false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserRole(ctx, "usr_1", "user"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(ctx, "usr_1")
	if got.TOTPEnrolled() || got.TOTPLastStep != 0 || got.PasswordHash != "h2" || got.MustChangePassword || got.Role != "user" {
		t.Fatalf("after resets: %+v", got)
	}
	if n, _ := s.CountActiveAdmins(ctx); n != 0 {
		t.Fatalf("active admins = %d", n)
	}
	if err := s.SetUserDisabled(ctx, "usr_1", true, now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(ctx, "usr_1")
	if !got.Disabled() {
		t.Fatal("not disabled")
	}
	if list, _ := s.ListUsers(ctx); len(list) != 1 {
		t.Fatalf("ListUsers = %d", len(list))
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	s.CreateUser(ctx, &User{ID: "usr_1", Username: "a", Role: "user", PasswordHash: "h", CreatedAt: now})
	for _, h := range []string{"s1", "s2", "s3"} {
		if err := s.CreateSession(ctx, &Session{IDHash: h, UserID: "usr_1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	ss, err := s.SessionByHash(ctx, "s1")
	if err != nil || ss.UserID != "usr_1" || ss.MFA {
		t.Fatalf("SessionByHash = %+v, %v", ss, err)
	}
	s.SetSessionMFA(ctx, "s1")
	s.TouchSession(ctx, "s1", now.Add(time.Hour))
	ss, _ = s.SessionByHash(ctx, "s1")
	if !ss.MFA || !ss.LastSeenAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("after touch: %+v", ss)
	}
	// Idle purge removes s2 and s3 (last seen at now), keeps s1.
	if n, _ := s.PurgeSessions(ctx, now.Add(time.Hour), now.Add(30*time.Minute)); n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	s.CreateSession(ctx, &Session{IDHash: "s4", UserID: "usr_1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := s.DeleteUserSessions(ctx, "usr_1", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByHash(ctx, "s4"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("s4 kept: %v", err)
	}
	if _, err := s.SessionByHash(ctx, "s1"); err != nil {
		t.Fatalf("kept session removed: %v", err)
	}
	// Deleting the user cascades to sessions.
	if err := s.DeleteUser(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByHash(ctx, "s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session survived user deletion: %v", err)
	}
}

func TestRevokeTokensBy(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	for i, by := range []string{"usr_1", "usr_1", "usr_2"} {
		s.CreateToken(ctx, &Token{ID: "tok_" + string(rune('a'+i)), Hash: "h" + string(rune('a'+i)), Kind: "personal",
			Scope: Scope{Buckets: []string{"*"}}, CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	}
	ids, err := s.RevokeTokensBy(ctx, "usr_1", now)
	if err != nil || len(ids) != 2 {
		t.Fatalf("RevokeTokensBy = %v, %v", ids, err)
	}
	if list, _ := s.ListTokens(ctx, now, ""); len(list) != 1 || list[0].CreatedBy != "usr_2" {
		t.Fatalf("remaining = %+v", list)
	}
}
