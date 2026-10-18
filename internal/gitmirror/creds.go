package gitmirror

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/config"
)

// credentials supplies the Authorization header value for upstream git
// requests. An empty value means anonymous access (public repos).
type credentials interface {
	header(ctx context.Context, owner, repo string) (string, error)
}

type anonymous struct{}

func (anonymous) header(context.Context, string, string) (string, error) { return "", nil }

// basicToken is a personal access token. GitHub (and GitLab) accept any
// user name with a token as the password.
type basicToken struct{ value string }

func (t basicToken) header(context.Context, string, string) (string, error) { return t.value, nil }

func basicHeader(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
}

func newCredentials(r config.GitRemote, run *runner, client *http.Client) (credentials, error) {
	c := r.Credentials
	switch {
	case c.Token.Value() != "":
		h := basicHeader(c.Token.Value())
		run.addSecret(c.Token.Value())
		run.addSecret(h)
		return basicToken{value: h}, nil
	case c.AppID != "":
		key, err := parseRSAKey([]byte(c.AppPrivateKey.Value()))
		if err != nil {
			return nil, fmt.Errorf("git remote %s: app_private_key: %w", r.Name, err)
		}
		api := c.APIURL
		if api == "" {
			api = defaultAPIURL(r.URL)
		}
		return &githubApp{appID: c.AppID, key: key, api: strings.TrimRight(api, "/"), client: client, run: run,
			now: time.Now, installs: map[string]installation{}, tokens: map[int64]appToken{}}, nil
	default:
		return anonymous{}, nil
	}
}

func defaultAPIURL(remote string) string {
	u, err := url.Parse(remote)
	if err == nil && strings.EqualFold(u.Host, "github.com") {
		return "https://api.github.com"
	}
	return strings.TrimRight(remote, "/") + "/api/v3"
}

func parseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM file")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("not an RSA private key in PKCS#1 or PKCS#8 form")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

// signJWT returns an RS256 JWT for GitHub App authentication. GitHub allows
// at most 10 minutes; iat is backdated to tolerate clock skew.
func signJWT(key *rsa.PrivateKey, appID string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

type installation struct {
	id      int64 // 0 = the app isn't installed for this owner
	checked time.Time
}

type appToken struct {
	raw     string
	header  string
	expires time.Time
}

// githubApp exchanges the app's JWT for installation tokens (valid 1 h) and
// refreshes them before they expire (FR-93). Installations are per owner.
type githubApp struct {
	appID  string
	key    *rsa.PrivateKey
	api    string
	client *http.Client
	run    *runner
	now    func() time.Time

	mu       sync.Mutex // serialises API calls; they are rare
	installs map[string]installation
	tokens   map[int64]appToken
}

// tokenRefreshMargin renews installation tokens this long before expiry, so
// a long fetch never starts with a token about to run out.
const tokenRefreshMargin = 10 * time.Minute

func (g *githubApp) header(ctx context.Context, owner, repo string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	inst, ok := g.installs[owner]
	if !ok || (inst.id == 0 && now.Sub(inst.checked) > 5*time.Minute) {
		id, err := g.installationID(ctx, owner, repo)
		if err != nil {
			return "", err
		}
		inst = installation{id: id, checked: now}
		g.installs[owner] = inst
	}
	if inst.id == 0 {
		return "", nil // not installed for this owner: try anonymously (public repos)
	}
	if t, ok := g.tokens[inst.id]; ok && now.Add(tokenRefreshMargin).Before(t.expires) {
		return t.header, nil
	}
	t, err := g.installationToken(ctx, inst.id)
	if err != nil {
		return "", err
	}
	if old, ok := g.tokens[inst.id]; ok {
		g.run.removeSecret(old.raw)
		g.run.removeSecret(old.header)
	}
	g.tokens[inst.id] = t
	return t.header, nil
}

func (g *githubApp) call(ctx context.Context, method, path string, out any) (int, error) {
	jwt, err := signJWT(g.key, g.appID, g.now())
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, g.api+path, nil) //nolint:gosec // G704: the API URL comes from config
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := g.client.Do(req) //nolint:gosec // G704: the API URL comes from config
	if err != nil {
		return 0, fmt.Errorf("github app: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, fmt.Errorf("github app: %s %s: status %d", method, path, resp.StatusCode)
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (g *githubApp) installationID(ctx context.Context, owner, repo string) (int64, error) {
	var v struct {
		ID int64 `json:"id"`
	}
	code, err := g.call(ctx, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/installation", &v)
	if code == http.StatusNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v.ID, nil
}

func (g *githubApp) installationToken(ctx context.Context, id int64) (appToken, error) {
	var v struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if _, err := g.call(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens", &v); err != nil {
		return appToken{}, err
	}
	if v.Token == "" {
		return appToken{}, errors.New("github app: empty installation token")
	}
	if v.ExpiresAt.IsZero() {
		v.ExpiresAt = g.now().Add(time.Hour)
	}
	h := basicHeader(v.Token)
	g.run.addSecret(v.Token)
	g.run.addSecret(h)
	return appToken{raw: v.Token, header: h, expires: v.ExpiresAt}, nil
}

// credEnv returns the environment that hands an Authorization header to
// git for URLs under base, through GIT_CONFIG_* (FR-93): it never appears
// in argv, in the mirror's config or in the remote URL.
func credEnv(base, header string) []string {
	if header == "" {
		return nil
	}
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http." + strings.TrimRight(base, "/") + "/.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: " + header,
	}
}
