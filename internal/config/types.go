// Package config loads and validates the proxy configuration.
//
// Secret values are never written inline in the YAML file. A secret field
// holds a reference such as `{file: /run/secrets/name}` and is resolved when
// the config is loaded (requirements SEC-10, SEC-11).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Secret is a reference to a secret stored in a file. The value is loaded by
// Resolve and never printed: String and MarshalYAML always mask it.
type Secret struct {
	File  string `yaml:"file"`
	value string
	set   bool
}

// UnmarshalYAML accepts only the mapping form `{file: path}`. A plain scalar
// is rejected so a secret can't be pasted into the config by mistake.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: secrets must be a reference like {file: /run/secrets/name}, not an inline value", n.Line)
	}
	var raw struct {
		File string `yaml:"file"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	if raw.File == "" {
		return fmt.Errorf("line %d: secret reference needs a 'file' path", n.Line)
	}
	s.File = raw.File
	return nil
}

// Configured reports whether the config references this secret at all.
func (s *Secret) Configured() bool { return s.File != "" }

// Resolve reads the secret file. Trailing newlines are trimmed because
// secret files are usually created with echo or an editor.
func (s *Secret) Resolve() error {
	if s.File == "" {
		return nil
	}
	b, err := os.ReadFile(s.File)
	if err != nil {
		return fmt.Errorf("reading secret file %s: %w", s.File, err)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" {
		return fmt.Errorf("secret file %s is empty", s.File)
	}
	s.value, s.set = v, true
	return nil
}

// Value returns the resolved secret, or "" if it isn't configured.
func (s *Secret) Value() string { return s.value }

func (s Secret) String() string {
	if s.File == "" {
		return "<unset>"
	}
	return "<secret from " + s.File + ">"
}

// MarshalYAML keeps secrets masked when a config is printed.
func (s Secret) MarshalYAML() (any, error) {
	if s.File == "" {
		return nil, nil
	}
	return map[string]string{"file": s.File}, nil
}

// Duration is a time.Duration that also accepts a "d" (days) suffix, e.g. "90d".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// ParseDuration parses Go durations plus whole days ("90d").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return v, nil
}

// ByteSize is a size in bytes that accepts units such as "200GiB" or "500MB".
type ByteSize int64

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize(v)
	return nil
}

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"B", 1},
}

// ParseByteSize parses a number with an optional binary or decimal unit.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	for _, u := range byteUnits {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("invalid size %q", s)
			}
			return int64(n * float64(u.mult)), nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n, nil
}

// Config is the whole configuration file.
type Config struct {
	Server  Server   `yaml:"server"`
	Auth    Auth     `yaml:"auth"`
	Storage Storage  `yaml:"storage"`
	Buckets []Bucket `yaml:"buckets"`
	Git     *Git     `yaml:"git"`
	Metrics Metrics  `yaml:"metrics"`
	Log     Log      `yaml:"log"`
}

type Server struct {
	DataListen    string   `yaml:"data_listen"`
	AdminListen   string   `yaml:"admin_listen"`
	PublicBaseURL string   `yaml:"public_base_url"`
	TLS           TLS      `yaml:"tls"`
	ShutdownGrace Duration `yaml:"shutdown_grace"`
}

// TLS is optional. With no files set the proxy serves plain HTTP (decision D7).
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether built-in TLS is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" }

type Auth struct {
	BootstrapAdminKey    Secret   `yaml:"bootstrap_admin_key"`
	InitialAdminUser     Secret   `yaml:"initial_admin_user"`
	InitialAdminPassword Secret   `yaml:"initial_admin_password"`
	DBEncryptionKey      Secret   `yaml:"db_encryption_key"`
	TokenDefaultTTL      Duration `yaml:"token_default_ttl"`
	TokenMaxTTL          Duration `yaml:"token_max_ttl"`
	PersonalTokenMaxTTL  Duration `yaml:"personal_token_max_ttl"`
	ValidationCacheTTL   Duration `yaml:"validation_cache_ttl"`
	// SessionIdleTimeout ends web UI sessions after this much inactivity (FR-61).
	SessionIdleTimeout Duration `yaml:"session_idle_timeout"`
	// UserTokenScope is the ceiling for tokens that UI users with the
	// "user" role create (FR-20). Unset: all buckets and all git remotes.
	UserTokenScope *TokenScope `yaml:"user_token_scope"`
}

// TokenScope limits what tokens may be issued for.
type TokenScope struct {
	Buckets []string        `yaml:"buckets"`
	Git     []TokenGitScope `yaml:"git"`
}

// TokenGitScope allows repos matching Repos ("owner/repo" or "owner/*") on Remote.
type TokenGitScope struct {
	Remote string   `yaml:"remote"`
	Repos  []string `yaml:"repos"`
}

type Storage struct {
	DBPath    string `yaml:"db_path"`
	CacheRoot string `yaml:"cache_root"`
}

type Bucket struct {
	Alias       string      `yaml:"alias"`
	Provider    string      `yaml:"provider"`
	Endpoint    string      `yaml:"endpoint"`
	Region      string      `yaml:"region"`
	Bucket      string      `yaml:"bucket"`
	Prefix      string      `yaml:"prefix"`
	PathStyle   *bool       `yaml:"path_style"`
	Credentials Credentials `yaml:"credentials"`
	Mode        string      `yaml:"mode"`
	Cache       BucketCache `yaml:"cache"`
	Timeouts    Timeouts    `yaml:"timeouts"`
}

type Credentials struct {
	AccessKeyID     Secret `yaml:"access_key_id"`
	SecretAccessKey Secret `yaml:"secret_access_key"`
}

type BucketCache struct {
	MaxSize     ByteSize `yaml:"max_size"`
	Freshness   string   `yaml:"freshness"`
	MaxAge      Duration `yaml:"max_age"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	ServeStale  bool     `yaml:"serve_stale"`
}

type Timeouts struct {
	Connect   Duration `yaml:"connect"`
	FirstByte Duration `yaml:"first_byte"`
	Idle      Duration `yaml:"idle"`
}

type Git struct {
	Storage    string      `yaml:"storage"`
	MaxSize    ByteSize    `yaml:"max_size"`
	EvictAfter Duration    `yaml:"evict_after"`
	Remotes    []GitRemote `yaml:"remotes"`
	// MaxConcurrency limits concurrent upload-pack processes (FR-93).
	// 0 means 4 per CPU, at least 8.
	MaxConcurrency int `yaml:"max_concurrency"`
	// FetchTimeout bounds one upstream clone or fetch.
	FetchTimeout Duration `yaml:"fetch_timeout"`
	// MaintenanceInterval is how often git maintenance and eviction run (FR-89).
	MaintenanceInterval Duration `yaml:"maintenance_interval"`
}

type GitRemote struct {
	Name            string         `yaml:"name"`
	URL             string         `yaml:"url"`
	Credentials     GitCredentials `yaml:"credentials"`
	Allow           []string       `yaml:"allow"`
	RefreshInterval Duration       `yaml:"refresh_interval"`
	LsRemoteCache   Duration       `yaml:"ls_remote_cache"`
	Prune           *bool          `yaml:"prune"`
	IncludePullRefs bool           `yaml:"include_pull_refs"`
	// UpstreamTimeout bounds the ls-remote freshness check; after it the
	// stale mirror is served (FR-84, FR-87).
	UpstreamTimeout Duration `yaml:"upstream_timeout"`
	// Seed lists owner/repo names mirrored at start-up (FR-83).
	Seed []string `yaml:"seed"`
}

type GitCredentials struct {
	Token         Secret `yaml:"token"`
	AppID         string `yaml:"app_id"`
	AppPrivateKey Secret `yaml:"app_private_key"`
	// APIURL is the GitHub API base for App auth. Default: https://api.github.com
	// for github.com, otherwise <url>/api/v3 (GitHub Enterprise Server).
	APIURL string `yaml:"api_url"`
}

type Metrics struct {
	BearerToken Secret `yaml:"bearer_token"`
}

type Log struct {
	Level  string `yaml:"level"`
	Access bool   `yaml:"access"`
}
