# Configuration reference

The config file is YAML, read from `--config`, `$PROXY_CONFIG`, or
`/etc/proxy/config.yaml`. Unknown keys are errors. `yproxy config check`
validates the file and every secret file it names without starting the
server, and lists all problems at once.

**Secrets** are never written in the file. Every secret is a reference to a
file, normally a Docker or Podman secret: `{ file: /run/secrets/name }`. A
plain value is rejected.

**Durations** take Go units plus `d` for days: `500ms`, `3s`, `10m`, `12h`,
`90d`. **Sizes** take `KiB`, `MiB`, `GiB`, `TiB` (and `KB`, `MB`, `GB`, `TB`).

A complete example is in [`deploy/config.example.yaml`](../deploy/config.example.yaml).

## server

| Key | Default | Meaning |
|---|---|---|
| `data_listen` | `:8080` | Address for builds: objects (`/t/...`) and git (`/git/...`). |
| `admin_listen` | `:8081` | Address for the web UI, `/api/v1`, `/metrics` and `/readyz`. Keep it off the build network if you can. |
| `public_base_url` | | Base URL of the data listener as clients see it. Used in the examples the API and UI show. |
| `tls.cert_file`, `tls.key_file` | empty | PEM files to serve HTTPS on both listeners. Empty means plain HTTP (D7), for example behind a TLS reverse proxy. |
| `shutdown_grace` | `30s` | How long running downloads may finish on `SIGTERM`. |

## auth

| Key | Default | Meaning |
|---|---|---|
| `bootstrap_admin_key` | | Secret. An admin API key that always works, for setup and automation. |
| `initial_admin_user`, `initial_admin_password` | | Secrets. Used once, when no users exist, to create the first admin. It must set up TOTP and change the password at first login. |
| `db_encryption_key` | | Secret. Encrypts TOTP secrets in the database. Required for UI logins; without it only API keys work. Don't lose it: TOTP has to be reset for every user if it changes. |
| `token_default_ttl` | `12h` | Lifetime of a build token when the request doesn't say. |
| `token_max_ttl` | `72h` | Longest build token lifetime. |
| `personal_token_max_ttl` | `90d` | Longest lifetime of a personal token made in the UI. |
| `validation_cache_ttl` | `5s` | How long a checked token stays cached. A revoked token stops working within this time at most (revoking from this proxy takes effect at once). |
| `session_idle_timeout` | `8h` | UI sessions end after this much inactivity (and after 24 h at most). |
| `user_token_scope` | everything | Ceiling for tokens that `user`-role accounts may create: `{ buckets: [...], git: [{ remote, repos: [...] }] }`. |

## storage

| Key | Default | Meaning |
|---|---|---|
| `db_path` | `/data/proxy.db` | SQLite database with users, API keys and token hashes. Back up the `/data` volume. |
| `cache_root` | `/cache` | Disk cache for buckets in `cache` mode, one directory per bucket. |

## buckets

A list. Each entry is one route `/t/<token>/<alias>/<key>` to one backend.

| Key | Default | Meaning |
|---|---|---|
| `alias` | | Name in the URL: lowercase letters, digits, `.`, `_`, `-`. Reserved: `t`, `git`, `api`, `healthz`, `readyz`, `metrics`. |
| `provider` | | `aws`, `r2`, `rustfs`, `minio` or `generic` (any S3-compatible store). |
| `endpoint` | AWS default | S3 endpoint URL. Required for everything but `aws`. |
| `region` | `auto` for R2, else `us-east-1` | SigV4 region. |
| `bucket` | | Bucket name on the backend. |
| `prefix` | | Key prefix inside the bucket; clients don't see it. |
| `path_style` | `true` for rustfs, minio, generic | Path-style instead of virtual-host addressing. |
| `credentials.access_key_id`, `credentials.secret_access_key` | | Secrets. Use read-only keys ([examples](backend-policies.md)). |
| `mode` | `passthrough` | `passthrough` streams from the backend; `cache` also keeps a copy on local disk. |
| `cache.max_size` | | Required in cache mode. Least recently used objects are evicted above 95 % until 85 % is reached. |
| `cache.freshness` | `immutable` | `immutable`: cached objects never change (right for sstate). `revalidate`: check with the backend after `max_age`. |
| `cache.max_age` | | With `revalidate`, how long a cached object is used without checking. |
| `cache.negative_ttl` | `30s` | How long a `404` is remembered. `0s` turns this off. |
| `cache.serve_stale` | `false` | Serve the cached copy when revalidation fails, instead of `502`/`504`. |
| `timeouts.connect` | `5s` | Connecting to the backend. |
| `timeouts.first_byte` | `30s` | Waiting for the backend's response headers. |
| `timeouts.idle` | `90s` | No data from the backend for this long ends the transfer. |

## git

Optional. Without it, `/git/...` isn't served.

| Key | Default | Meaning |
|---|---|---|
| `storage` | `/git` | Mirrors, plus git's own `HOME` and temp files. Its own volume. |
| `max_size` | | Least recently used mirrors are removed above this. |
| `evict_after` | `90d` | Mirrors not used for this long are removed. |
| `max_concurrency` | 4 per CPU, at least 8 | `git upload-pack` processes at once; more requests wait. |
| `fetch_timeout` | `30m` | One upstream clone or fetch. |
| `maintenance_interval` | `1h` | How often `git maintenance run --auto` and eviction run. |

Each entry of `remotes`:

| Key | Default | Meaning |
|---|---|---|
| `name` | | Name in the URL: `/git/<name>/<owner>/<repo>.git`. |
| `url` | | Upstream base URL, for example `https://github.com`. |
| `credentials.token` | | Secret. A token for private repos (GitHub: a fine-grained read-only token). |
| `credentials.app_id`, `credentials.app_private_key` | | A GitHub App instead of a token; installation tokens are refreshed automatically. |
| `credentials.api_url` | `https://api.github.com` | GitHub API for App tokens (GitHub Enterprise). |
| `allow` | | Required. `owner/repo` or `owner/*` patterns that may be mirrored. Others get `404`. |
| `seed` | | Repos to mirror at start-up. |
| `refresh_interval` | `10m` | Background check of every mirror. |
| `ls_remote_cache` | `3s` | How long an upstream ref check is reused. A commit pushed upstream is visible to clients after at most this long. |
| `upstream_timeout` | `3s` | If upstream doesn't answer the ref check in time, the mirror is served as it is. |
| `prune` | `true` | Remove branches and tags deleted upstream. Commits fetched by SHA stay. |
| `include_pull_refs` | `false` | Also mirror `refs/pull/*`. Makes every check heavier. |

## metrics

| Key | Default | Meaning |
|---|---|---|
| `bearer_token` | | Secret. If set, `/metrics` needs `Authorization: Bearer <token>`. |

## log

| Key | Default | Meaning |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` or `error`. Logs are JSON on stdout. |
| `access` | `false` | One line per object and git request (token ID, never the token). |

## Environment variables

Plain settings can be overridden with `PROXY_DATA_LISTEN`, `PROXY_ADMIN_LISTEN`,
`PROXY_PUBLIC_BASE_URL`, `PROXY_DB_PATH`, `PROXY_CACHE_ROOT`, `PROXY_LOG_LEVEL`,
`PROXY_TLS_CERT_FILE` and `PROXY_TLS_KEY_FILE`.

Secrets can only be overridden with a file path: `ADMIN_API_KEY_FILE`,
`INITIAL_ADMIN_USER_FILE`, `INITIAL_ADMIN_PASSWORD_FILE`,
`DB_ENCRYPTION_KEY_FILE` and `METRICS_TOKEN_FILE`.
