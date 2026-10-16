package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is used when neither --config nor PROXY_CONFIG is given.
const DefaultPath = "/etc/proxy/config.yaml"

// Load reads the file at path, applies defaults and environment overrides,
// validates the result and resolves every referenced secret.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return Parse(b, os.LookupEnv)
}

// Parse is Load without the file read; lookup is normally os.LookupEnv.
func Parse(b []byte, lookup func(string) (string, bool)) (*Config, error) {
	return parse(b, lookup, true)
}

func parse(b []byte, lookup func(string) (string, bool), resolve bool) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	c.applyDefaults()
	c.applyEnv(lookup)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !resolve {
		return &c, nil
	}
	if err := c.resolveSecrets(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	def := func(d *Duration, v time.Duration) {
		if *d == 0 {
			*d = Duration(v)
		}
	}
	str := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	str(&c.Server.DataListen, ":8080")
	str(&c.Server.AdminListen, ":8081")
	def(&c.Server.ShutdownGrace, 30*time.Second)
	def(&c.Auth.TokenDefaultTTL, 12*time.Hour)
	def(&c.Auth.TokenMaxTTL, 72*time.Hour)
	def(&c.Auth.PersonalTokenMaxTTL, 90*24*time.Hour)
	def(&c.Auth.ValidationCacheTTL, 5*time.Second)
	str(&c.Storage.DBPath, "/data/proxy.db")
	str(&c.Storage.CacheRoot, "/cache")
	str(&c.Log.Level, "info")

	for i := range c.Buckets {
		b := &c.Buckets[i]
		str(&b.Mode, "passthrough")
		if b.PathStyle == nil {
			// Self-hosted stores usually need path-style addressing; AWS and R2 don't.
			ps := b.Provider == "rustfs" || b.Provider == "minio" || b.Provider == "generic"
			b.PathStyle = &ps
		}
		switch b.Provider {
		case "r2":
			str(&b.Region, "auto")
		default:
			str(&b.Region, "us-east-1")
		}
		str(&b.Cache.Freshness, "immutable")
		def(&b.Cache.NegativeTTL, 30*time.Second)
		def(&b.Timeouts.Connect, 5*time.Second)
		def(&b.Timeouts.FirstByte, 30*time.Second)
		def(&b.Timeouts.Idle, 90*time.Second)
	}

	if c.Git != nil {
		str(&c.Git.Storage, "/git")
		def(&c.Git.EvictAfter, 90*24*time.Hour)
		for i := range c.Git.Remotes {
			r := &c.Git.Remotes[i]
			def(&r.RefreshInterval, 10*time.Minute)
			def(&r.LsRemoteCache, 3*time.Second)
			if r.Prune == nil {
				t := true
				r.Prune = &t
			}
		}
	}
}

// secretEnv maps *_FILE environment variables to the secret they override.
func (c *Config) secretEnv() map[string]*Secret {
	return map[string]*Secret{
		"ADMIN_API_KEY_FILE":          &c.Auth.BootstrapAdminKey,
		"INITIAL_ADMIN_USER_FILE":     &c.Auth.InitialAdminUser,
		"INITIAL_ADMIN_PASSWORD_FILE": &c.Auth.InitialAdminPassword,
		"DB_ENCRYPTION_KEY_FILE":      &c.Auth.DBEncryptionKey,
		"METRICS_TOKEN_FILE":          &c.Metrics.BearerToken,
	}
}

// applyEnv applies PROXY_* overrides for plain settings and *_FILE variables
// for secrets (CFG-1). Secrets can't be set from plain environment values.
func (c *Config) applyEnv(lookup func(string) (string, bool)) {
	plain := map[string]*string{
		"PROXY_DATA_LISTEN":     &c.Server.DataListen,
		"PROXY_ADMIN_LISTEN":    &c.Server.AdminListen,
		"PROXY_PUBLIC_BASE_URL": &c.Server.PublicBaseURL,
		"PROXY_DB_PATH":         &c.Storage.DBPath,
		"PROXY_CACHE_ROOT":      &c.Storage.CacheRoot,
		"PROXY_LOG_LEVEL":       &c.Log.Level,
		"PROXY_TLS_CERT_FILE":   &c.Server.TLS.CertFile,
		"PROXY_TLS_KEY_FILE":    &c.Server.TLS.KeyFile,
	}
	for k, p := range plain {
		if v, ok := lookup(k); ok && v != "" {
			*p = v
		}
	}
	for k, s := range c.secretEnv() {
		if v, ok := lookup(k); ok && v != "" {
			s.File = v
		}
	}
}

var (
	aliasRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	reservedName = map[string]bool{"t": true, "git": true, "api": true, "healthz": true, "readyz": true, "metrics": true}
)

// Validate checks the config without touching secret files, so that
// `yproxy config check` can explain every problem at once.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for name, addr := range map[string]string{"server.data_listen": c.Server.DataListen, "server.admin_listen": c.Server.AdminListen} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			add("%s: %q is not a host:port address", name, addr)
		}
	}
	if c.Server.DataListen == c.Server.AdminListen {
		add("server.data_listen and server.admin_listen must differ")
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		add("server.tls: set both cert_file and key_file, or neither")
	}
	if c.Server.PublicBaseURL != "" {
		if u, err := url.Parse(c.Server.PublicBaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("server.public_base_url: %q must be an http:// or https:// URL", c.Server.PublicBaseURL)
		}
	}
	if c.Auth.TokenDefaultTTL > c.Auth.TokenMaxTTL {
		add("auth.token_default_ttl (%s) is longer than auth.token_max_ttl (%s)", c.Auth.TokenDefaultTTL.D(), c.Auth.TokenMaxTTL.D())
	}
	if c.Auth.ValidationCacheTTL.D() > 5*time.Second {
		add("auth.validation_cache_ttl must be at most 5s so revocation takes effect quickly")
	}
	if c.Auth.InitialAdminUser.Configured() != c.Auth.InitialAdminPassword.Configured() {
		add("auth: set both initial_admin_user and initial_admin_password, or neither")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level: %q must be debug, info, warn or error", c.Log.Level)
	}

	seen := map[string]bool{}
	for i, b := range c.Buckets {
		where := fmt.Sprintf("buckets[%d]", i)
		if b.Alias != "" {
			where = fmt.Sprintf("buckets[%s]", b.Alias)
		}
		switch {
		case !aliasRe.MatchString(b.Alias):
			add("%s: alias %q must be lowercase letters, digits, '.', '_' or '-'", where, b.Alias)
		case reservedName[b.Alias]:
			add("%s: alias %q is reserved", where, b.Alias)
		case seen[b.Alias]:
			add("%s: duplicate alias", where)
		}
		seen[b.Alias] = true
		switch b.Provider {
		case "aws", "r2", "rustfs", "minio", "generic":
		default:
			add("%s: provider %q must be aws, r2, rustfs, minio or generic", where, b.Provider)
		}
		if b.Provider != "aws" && b.Endpoint == "" {
			add("%s: endpoint is required for provider %q", where, b.Provider)
		}
		if b.Endpoint != "" {
			if u, err := url.Parse(b.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				add("%s: endpoint %q must be an http:// or https:// URL", where, b.Endpoint)
			}
		}
		if b.Bucket == "" {
			add("%s: bucket is required", where)
		}
		if strings.HasPrefix(b.Prefix, "/") || strings.Contains(b.Prefix, "..") {
			add("%s: prefix must be relative and must not contain '..'", where)
		}
		if !b.Credentials.AccessKeyID.Configured() || !b.Credentials.SecretAccessKey.Configured() {
			add("%s: credentials.access_key_id and credentials.secret_access_key are required", where)
		}
		switch b.Mode {
		case "passthrough":
		case "cache":
			if b.Cache.MaxSize <= 0 {
				add("%s: cache.max_size is required in cache mode", where)
			}
			switch b.Cache.Freshness {
			case "immutable":
			case "revalidate":
				if b.Cache.MaxAge <= 0 {
					add("%s: cache.max_age is required when freshness is revalidate", where)
				}
			default:
				add("%s: cache.freshness %q must be immutable or revalidate", where, b.Cache.Freshness)
			}
		default:
			add("%s: mode %q must be passthrough or cache", where, b.Mode)
		}
	}

	if c.Git != nil {
		names := map[string]bool{}
		for i, r := range c.Git.Remotes {
			where := fmt.Sprintf("git.remotes[%d]", i)
			if !aliasRe.MatchString(r.Name) {
				add("%s: name %q must be lowercase letters, digits, '.', '_' or '-'", where, r.Name)
			} else if names[r.Name] {
				add("%s: duplicate remote name %q", where, r.Name)
			}
			names[r.Name] = true
			if u, err := url.Parse(r.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				add("%s: url %q must be an http(s) URL without credentials", where, r.URL)
			}
			if len(r.Allow) == 0 {
				add("%s: allow must list at least one owner/repo pattern", where)
			}
			for _, p := range r.Allow {
				if p == "*" || p == "*/*" || strings.Count(p, "/") != 1 {
					add("%s: allow pattern %q must be owner/repo or owner/*", where, p)
				}
			}
			if r.Credentials.Token.Configured() && (r.Credentials.AppID != "" || r.Credentials.AppPrivateKey.Configured()) {
				add("%s: credentials: use either token or a GitHub App, not both", where)
			}
			if (r.Credentials.AppID == "") != !r.Credentials.AppPrivateKey.Configured() {
				add("%s: credentials: a GitHub App needs both app_id and app_private_key", where)
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Config) resolveSecrets() error {
	var errs []error
	res := func(s *Secret) {
		if err := s.Resolve(); err != nil {
			errs = append(errs, err)
		}
	}
	res(&c.Auth.BootstrapAdminKey)
	res(&c.Auth.InitialAdminUser)
	res(&c.Auth.InitialAdminPassword)
	res(&c.Auth.DBEncryptionKey)
	res(&c.Metrics.BearerToken)
	for i := range c.Buckets {
		res(&c.Buckets[i].Credentials.AccessKeyID)
		res(&c.Buckets[i].Credentials.SecretAccessKey)
	}
	if c.Git != nil {
		for i := range c.Git.Remotes {
			res(&c.Git.Remotes[i].Credentials.Token)
			res(&c.Git.Remotes[i].Credentials.AppPrivateKey)
		}
	}
	return errors.Join(errs...)
}

// CacheEnabled reports whether any bucket uses the disk cache.
func (c *Config) CacheEnabled() bool {
	for _, b := range c.Buckets {
		if b.Mode == "cache" {
			return true
		}
	}
	return false
}
