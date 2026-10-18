package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSecret(t *testing.T, dir, name, value string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noEnv(string) (string, bool) { return "", false }

func validConfig(t *testing.T) (string, string) {
	dir := t.TempDir()
	ak := writeSecret(t, dir, "ak", "AKIAEXAMPLE\n")
	sk := writeSecret(t, dir, "sk", "secretvalue\n")
	return dir, `
server:
  public_base_url: "http://cache.lan:8080"
buckets:
  - alias: sstate
    provider: rustfs
    endpoint: http://rustfs.lan:9000
    bucket: yocto-sstate
    credentials:
      access_key_id: { file: ` + ak + ` }
      secret_access_key: { file: ` + sk + ` }
  - alias: sstate-cloud
    provider: r2
    endpoint: https://acct.r2.cloudflarestorage.com
    bucket: yocto-sstate
    credentials:
      access_key_id: { file: ` + ak + ` }
      secret_access_key: { file: ` + sk + ` }
    mode: cache
    cache: { max_size: 200GiB, negative_ttl: 0s }
git:
  remotes:
    - name: github
      url: https://github.com
      allow: ["acme/*"]
`
}

func TestParseValidConfig(t *testing.T) {
	_, yml := validConfig(t)
	c, err := Parse([]byte(yml), noEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Server.DataListen != ":8080" || c.Server.AdminListen != ":8081" {
		t.Errorf("listener defaults not applied: %+v", c.Server)
	}
	if got := c.Buckets[0].Credentials.SecretAccessKey.Value(); got != "secretvalue" {
		t.Errorf("secret not resolved and trimmed: %q", got)
	}
	if !*c.Buckets[0].PathStyle || *c.Buckets[1].PathStyle {
		t.Errorf("path style defaults wrong: rustfs=%v r2=%v", *c.Buckets[0].PathStyle, *c.Buckets[1].PathStyle)
	}
	if c.Buckets[1].Region != "auto" {
		t.Errorf("r2 region default = %q, want auto", c.Buckets[1].Region)
	}
	if c.Buckets[1].Cache.MaxSize != 200<<30 {
		t.Errorf("max_size = %d", c.Buckets[1].Cache.MaxSize)
	}
	if c.Git.Remotes[0].LsRemoteCache.D() != 3*time.Second || !*c.Git.Remotes[0].Prune {
		t.Errorf("git defaults not applied: %+v", c.Git.Remotes[0])
	}
	if r := c.Git.Remotes[0]; r.UpstreamTimeout.D() != 3*time.Second || c.Git.FetchTimeout.D() != 30*time.Minute || c.Git.MaintenanceInterval.D() != time.Hour || !r.Allows("ACME/Repo") || r.Allows("other/x") {
		t.Errorf("git defaults or allowlist wrong: %+v", r)
	}
	if c.Git.EvictAfter.D() != 90*24*time.Hour {
		t.Errorf("evict_after default = %s", c.Git.EvictAfter.D())
	}
	if !c.CacheEnabled() {
		t.Error("CacheEnabled should be true")
	}
}

func TestInlineSecretRejected(t *testing.T) {
	yml := `
buckets:
  - alias: s
    provider: aws
    bucket: b
    credentials:
      access_key_id: AKIAINLINE
      secret_access_key: { file: /x }
`
	_, err := Parse([]byte(yml), noEnv)
	if err == nil || !strings.Contains(err.Error(), "not an inline value") {
		t.Fatalf("want inline secret error, got %v", err)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	_, yml := validConfig(t)
	c, err := Parse([]byte(yml), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Buckets[0].Credentials.SecretAccessKey
	if strings.Contains(s.String(), "secretvalue") {
		t.Errorf("String leaks secret: %s", s.String())
	}
}

func TestValidationCollectsAllErrors(t *testing.T) {
	yml := `
server:
  data_listen: ":9000"
  admin_listen: ":9000"
  tls: { cert_file: /c }
buckets:
  - alias: Bad_Alias
    provider: dropbox
    credentials: {}
    mode: turbo
  - alias: git
    provider: aws
    bucket: b
    mode: cache
    credentials:
      access_key_id: { file: /a }
      secret_access_key: { file: /b }
git:
  remotes:
    - name: github
      url: https://user:pw@github.com
      allow: ["*"]
      seed: ["other/repo"]
      credentials: { api_url: "ftp://x" }
  max_concurrency: -1
`
	_, err := Parse([]byte(yml), noEnv)
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{
		"must differ",
		"set both cert_file and key_file",
		"alias \"Bad_Alias\"",
		"provider \"dropbox\"",
		"bucket is required",
		"credentials.access_key_id",
		"mode \"turbo\"",
		"alias \"git\" is reserved",
		"cache.max_size is required",
		"without credentials",
		"allow pattern \"*\"",
		"seed \"other/repo\"",
		"credentials.api_url",
		"max_concurrency",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing error %q in:\n%v", want, err)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte("server:\n  data_listn: \":1\"\n"), noEnv)
	if err == nil || !strings.Contains(err.Error(), "data_listn") {
		t.Fatalf("want unknown field error, got %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	dir, yml := validConfig(t)
	key := writeSecret(t, dir, "admin", "adminkey")
	env := map[string]string{
		"PROXY_DATA_LISTEN":  ":18080",
		"ADMIN_API_KEY_FILE": key,
	}
	c, err := Parse([]byte(yml), func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.DataListen != ":18080" {
		t.Errorf("PROXY_DATA_LISTEN not applied: %s", c.Server.DataListen)
	}
	if c.Auth.BootstrapAdminKey.Value() != "adminkey" {
		t.Errorf("ADMIN_API_KEY_FILE not applied")
	}
}

func TestMissingSecretFile(t *testing.T) {
	yml := `
buckets:
  - alias: s
    provider: aws
    bucket: b
    credentials:
      access_key_id: { file: /nonexistent/ak }
      secret_access_key: { file: /nonexistent/sk }
`
	_, err := Parse([]byte(yml), noEnv)
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/ak") {
		t.Fatalf("want missing secret error, got %v", err)
	}
}

func TestParseHelpers(t *testing.T) {
	if d, err := ParseDuration("90d"); err != nil || d != 90*24*time.Hour {
		t.Errorf("90d = %v, %v", d, err)
	}
	if d, err := ParseDuration("1h30m"); err != nil || d != 90*time.Minute {
		t.Errorf("1h30m = %v, %v", d, err)
	}
	if _, err := ParseDuration("soon"); err == nil {
		t.Error("expected error for 'soon'")
	}
	for in, want := range map[string]int64{"200GiB": 200 << 30, "500MB": 500e6, "1024": 1024, "1.5KiB": 1536} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%s = %d, %v; want %d", in, got, err, want)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	b, err := os.ReadFile("../../deploy/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(b, noEnv, false); err != nil {
		t.Fatalf("deploy/config.example.yaml is invalid: %v", err)
	}
}
