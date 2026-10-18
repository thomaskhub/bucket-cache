# bucket-cache

A caching proxy for Yocto/BitBake builds. It serves sstate and download-cache
objects from S3-compatible buckets (AWS S3, Cloudflare R2, RustFS, MinIO) over
plain HTTP or HTTPS with one short-lived token per build, and acts as a
read-only, company-wide git mirror cache.

The full requirements and the implementation plan live in the project's
`requirements/` folder (`s3-https-proxy-requirements.md`,
`implementation-plan.md`).

## Status

Stage M0 (skeleton) is done:

- Config loading with secrets only from files (`{file: /run/secrets/...}`),
  `*_FILE` and `PROXY_*` environment overrides, and full validation.
- Data listener (`:8080`) and admin listener (`:8081`) with `/healthz`,
  `/readyz` and Prometheus `/metrics` (optionally behind a bearer token).
- Docker image: non-root, read-only root filesystem, volumes `/data`,
  `/cache` and `/git`, built-in `healthcheck` command.
- CI: vet, race tests, lint, license check, a multi-arch image build and SBOMs.

Stage M1 (S3 pass-through and tokens) is done:

- `GET`/`HEAD` at `/t/{token}/{bucket}/{key}` (or `/{bucket}/{key}` with a
  Bearer or Basic token), with Range and conditional requests, streaming, and
  `404` for missing objects so BitBake falls back quickly.
- Tokens and API keys (`admin`, `token-issuer` with a scope/TTL ceiling)
  stored as hashes in SQLite; `DELETE /api/v1/tokens/self` for builds.
- Only unknown tokens are rate-limited; expired or revoked tokens get `401`
  and show up in `yproxy_auth_dead_token_requests_total`.

Also done: the git mirror cache (see [Git mirror](#git-mirror)) and users
with TOTP login and the web UI (see [Web UI and users](#web-ui-and-users)).

## Creating a token for a build

```sh
TOKEN=$(curl -fsS -X POST http://cache.lan:8081/api/v1/tokens \
  -H "Authorization: Bearer $PROXY_ISSUER_KEY" \
  -d '{"buckets":["sstate"],"ttl":"6h","description":"pipeline 4711"}' | jq -r .token)
curl -I "http://cache.lan:8080/t/$TOKEN/sstate/some/key"   # 200 or 404, never 401
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://cache.lan:8081/api/v1/tokens/self
```

## Git mirror

The proxy is also a read-only, company-wide git mirror. Clients use git
smart HTTP (protocol v0 and v2) on the data listener:

```
http(s)://proxy/git/{remote}/{owner}/{repo}.git          # token as Basic password (any user name)
http(s)://proxy/t/{token}/git/{remote}/{owner}/{repo}.git # token in the path
```

`.git` is optional, `owner/repo` is case-insensitive and `//` is accepted.
Only repos matching the remote's `allow` patterns are served (others get
`404`), a token only reads the repos in its `git` scope (`403` otherwise),
and push gets `403`. The first request for a repo clones it into a bare
mirror under `git.storage`; later requests are served from the mirror after
a quick `ls-remote` check of upstream (cached for `ls_remote_cache`, 3 s),
so a branch or `SRCREV` pushed seconds ago is visible to the next build. If
upstream doesn't answer within `upstream_timeout`, the mirror is served as
is. Commits fetched by SHA that are on no branch are kept under the hidden
`refs/proxy/keep/` refs. Upstream credentials stay in the proxy: they are
handed to git through the environment, never on its command line or in a
mirror's config.

A token for git needs a `git` scope:

```sh
curl -fsS -X POST http://cache.lan:8081/api/v1/tokens -H "Authorization: Bearer $PROXY_ISSUER_KEY" \
  -d '{"buckets":["sstate"],"git":[{"remote":"github","repos":["acme/*"]}],"ttl":"6h"}'
```

### Client setup

Rewrite GitHub URLs to the proxy (CI uses the build token, developers a
personal token). This also covers submodules and BitBake's git fetcher,
which runs git with the user's `HOME`:

```sh
P="https://ci:${SSTATE_PROXY_TOKEN}@cache.example.com/git/github/"
git config --global url."$P".insteadOf "https://github.com/"
git config --global --add url."$P".insteadOf "git@github.com:"          # SSH-style URLs
git config --global --add url."$P".insteadOf "ssh://git@github.com/"    # BitBake protocol=ssh
git clone https://github.com/acme/meta-acme.git                         # served by the proxy
```

All three rules share one config key, so the second and third need `--add`;
without it each command replaces the previous rule.

The path-token form works the same way
(`url."https://cache.example.com/t/${SSTATE_PROXY_TOKEN}/git/github/".insteadOf ...`)
for tools that can't send credentials. On shared runners use a per-job
`HOME` so the token doesn't stay in `~/.gitconfig`.

### BitBake without a git config

BitBake's git fetcher drops passwords from URLs, so a premirror must use the
path-token form:

```bitbake
PREMIRRORS:prepend = "git://github.com/.* git://cache.example.com/t/${SSTATE_PROXY_TOKEN}/git/github/PATH;protocol=https \n"
BB_BASEHASH_IGNORE_VARS:append = " SSTATE_PROXY_TOKEN"
```

BitBake stores that URL as the remote of its DL_DIR clone, so the token ends
up in DL_DIR and in mirror tarballs made from it; the `insteadOf` rules
above don't have this problem and are preferred.

### Admin API

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/v1/repos` | any API key | Mirrors (size, last fetch, last error, stale) and remotes |
| `POST /api/v1/repos/{remote}/{owner}/{repo}/refresh` | admin | Fetch now; creates (pre-seeds) the mirror if missing |
| `DELETE /api/v1/repos/{remote}/{owner}/{repo}` | admin | Remove a mirror |

`git maintenance run --auto` runs on every mirror each
`maintenance_interval`; mirrors unused for `evict_after` are removed, and
the least recently used ones go when the total exceeds `max_size`. Metrics
are under `yproxy_git_*`; `/readyz` lists stale mirrors under
`details.git`. The proxy needs git 2.32 or newer.

## Commands

```sh
yproxy serve --config /etc/proxy/config.yaml
yproxy config check --config config.yaml   # validates config and secret files
yproxy healthcheck                         # used by the Docker HEALTHCHECK
yproxy user create [--admin] NAME          # web UI user; prints a one-time password
yproxy user reset-password NAME            # new one-time password, unlocks the account
yproxy user reset-totp NAME                # lost phone: the user enrols TOTP again
yproxy user list
yproxy version
```

`user create` and `user reset-password` take `--password-file PATH` or
`--password-stdin` instead of generating a password. Passwords are never
accepted as command-line arguments. In Docker: `docker exec -it yproxy yproxy user reset-totp admin`.

## Web UI and users

The UI is served on the admin listener at `/` (for example
`http://cache.lan:8081/`). It has pages for the dashboard, tokens (CI and
personal tokens, shown once with copy buttons), API keys, buckets (with a
connection test) and users. All assets (Alpine.js, Tailwind CSS) are embedded,
so it works without internet access, and it uses only the `/api/v1` endpoints.

- **First start:** if there are no users, the admin is created from the
  `auth.initial_admin_user` and `auth.initial_admin_password` secret files.
  `auth.db_encryption_key` must be set; it encrypts the TOTP secrets
  (AES-256-GCM). Without it, UI login is disabled.
- **Login** needs the password and a 6-digit TOTP code (RFC 6238, any
  authenticator app). Each code works once. At first login (and after an admin
  reset) the user must scan a QR code to set up TOTP, then choose a new
  password, before reaching any other page.
- **Lockout:** 5 failed logins in a row lock the account for 15 minutes;
  failures are also rate-limited per client IP. `yproxy user reset-password`
  or the Users page unlocks it.
- **Roles:** `admin` can do everything. `user` can create, list and revoke
  their own tokens, including long-lived personal tokens (up to
  `auth.personal_token_max_ttl`, default 90d), and view buckets. Optionally
  limit what users may issue tokens for with `auth.user_token_scope`.
  Disabling or deleting a user revokes the tokens they created.
- **Sessions** are server-side (only a hash of the cookie is stored), expire
  after `auth.session_idle_timeout` (default 8h) of inactivity and after 24h
  at most. The cookie is `HttpOnly` and `SameSite=Strict`, and `Secure` when the
  UI is reached over HTTPS (built-in TLS, or a reverse proxy that sets
  `X-Forwarded-Proto: https`). State-changing requests also need the session's
  CSRF token in `X-CSRF-Token`.
- **Plain HTTP** works, but the UI shows a warning banner: passwords and
  session cookies then cross the network unencrypted.
- The UI sends a strict Content Security Policy (no inline or eval'd scripts;
  Alpine's CSP build), `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`.

The UI login endpoints are `POST /api/v1/session` (login), `GET` and `DELETE`
`/api/v1/session`, `POST /api/v1/session/totp` and `/session/totp/confirm`
(enrolment) and `POST /api/v1/session/password`. Admins manage users with
`GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{id}` and
`POST /api/v1/users/{id}/reset-password|reset-totp`.

**Changing the UI:** pages live in `internal/ui/static/pages/<id>.html` with a
script `internal/ui/static/js/pages/<id>.js` that calls `YP.page({id, title,
role, order}, factory)`; both are picked up automatically, including the nav
entry. The vendored files are fetched by `scripts/vendor-ui.sh` (pinned
versions); run `scripts/vendor-ui.sh css` after using Tailwind classes that
are not in `internal/ui/static/css/app.css` yet.

The browser test (`internal/ui/browser_test.go`) drives headless Chrome or
Chromium with chromedp. It finds the browser via `CHROME_PATH`,
`PLAYWRIGHT_BROWSERS_PATH` or `$PATH` and skips if there is none (CI sets
`YPROXY_BROWSER_TEST=require` so it can't be skipped silently).

## Quick start (Docker)

```sh
cd deploy
mkdir -p secrets
for s in admin_api_key db_encryption_key metrics_token; do openssl rand -hex 32 > secrets/$s; done
echo admin > secrets/initial_admin_user
openssl rand -base64 18 > secrets/initial_admin_password
# add your bucket and GitHub credentials as files in secrets/, then edit config.example.yaml
docker compose up -d
```

The proxy serves plain HTTP by default. Use TLS (`server.tls`) or a TLS
reverse proxy when traffic crosses untrusted networks.

## Debug instance

`scripts/debug.sh` starts a throwaway instance on localhost: the proxy with
debug and access logging, a RustFS server with a `debug-sstate` bucket and a
test object, and a 12-hour build token. It prints the token, curl examples and
the `SSTATE_MIRRORS` line for `local.conf`.

```sh
scripts/debug.sh          # build and start (Podman, or Docker if Podman is missing)
scripts/debug.sh token    # create another token
scripts/debug.sh logs     # follow the proxy logs
scripts/debug.sh down     # stop; add --wipe to delete all data
```

It needs `podman` with `podman-compose` (`apt install podman-compose` or
`pip install podman-compose`), or Docker with Compose (`CONTAINER_ENGINE=docker`).
Change the ports with `DATA_PORT`, `ADMIN_PORT` and `RUSTFS_PORT`.

## Licenses

The proxy is licensed under the Apache License 2.0 (see `LICENSE` and `NOTICE`). Every Go dependency must be MIT, BSD, ISC or
Apache-2.0; CI enforces this with `go-licenses` (see
`THIRD_PARTY_LICENSES.csv`, which also lists the embedded UI assets; their
license texts are in `internal/ui/static/vendor/`). The image also contains the `git` program
(GPL-2.0), which runs as a separate process and is not linked into the proxy;
its license is in `/usr/share/doc/git` inside the image.

## SBOM

Every CI run publishes two SBOMs as workflow artifacts:

- `sbom-go`: a CycloneDX file (`yproxy.cdx.json`) listing every Go module
  compiled into `yproxy`, with versions, hashes and detected licenses.
- `sbom-image.spdx.json`: an SPDX file for the whole container image,
  including the Debian packages such as `git`.

To make the Go SBOM locally:

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
cyclonedx-gomod app -json -licenses -main cmd/yproxy -output yproxy.cdx.json .
```

Release images (M6) will carry the SBOM as a signed attestation in the registry.
