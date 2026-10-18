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

Stage M3 (disk cache) is done; see "Disk cache" below. The UI and the git
mirror follow in stages M4–M6, and the Yocto end-to-end test in M2.

## Disk cache

Buckets with `mode: cache` keep a local copy under `storage.cache_root/<alias>`
(stage M3). A miss is streamed to the client while it is written to a temp
file, and concurrent requests for the same key share one backend fetch. The
file is fsynced and renamed into place only when it is complete, so a crash or
a broken transfer never leaves a partial object that gets served; leftover
temp files are removed at startup. If the client disconnects, the download
still finishes in the background and is cached. File names are SHA-256 hashes
of alias and key, never the key itself.

- `HEAD`, `Range` and conditional requests on a hit are answered from local
  metadata and never reach the backend. Responses carry `X-Cache: HIT`,
  `MISS`, `STALE` or `BYPASS` (pass-through buckets and objects larger than
  `max_size`).
- `freshness: immutable` never revalidates; `revalidate` sends a conditional
  `HEAD` once `max_age` has passed. With `serve_stale: true` cached objects
  are still served (`STALE`) when that check fails.
- 404s are cached for `negative_ttl` (default 30s, `0s` disables).
- An LRU sweeper keeps usage between 85 % and 95 % of `max_size`.
- Stats and purge (admin API key):

```sh
curl -H "Authorization: Bearer $ADMIN_KEY" http://cache.lan:8081/api/v1/buckets/sstate-cloud/cache
curl -X DELETE -H "Authorization: Bearer $ADMIN_KEY" "http://cache.lan:8081/api/v1/buckets/sstate-cloud/cache?prefix=kirkstone/"
# ?key=<key> purges one object; no parameter purges the whole bucket
```

Metrics: `yproxy_cache_requests_total{bucket,result}`, `yproxy_cache_hit_bytes_total`,
`yproxy_cache_fill_bytes_total`, `yproxy_cache_fill_errors_total`,
`yproxy_cache_evictions_total`, `yproxy_cache_size_bytes`, `yproxy_cache_objects`.

## Creating a token for a build

```sh
TOKEN=$(curl -fsS -X POST http://cache.lan:8081/api/v1/tokens \
  -H "Authorization: Bearer $PROXY_ISSUER_KEY" \
  -d '{"buckets":["sstate"],"ttl":"6h","description":"pipeline 4711"}' | jq -r .token)
curl -I "http://cache.lan:8080/t/$TOKEN/sstate/some/key"   # 200 or 404, never 401
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://cache.lan:8081/api/v1/tokens/self
```

## Commands

```sh
yproxy serve --config /etc/proxy/config.yaml
yproxy config check --config config.yaml   # validates config and secret files
yproxy healthcheck                         # used by the Docker HEALTHCHECK
yproxy version
```

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
`THIRD_PARTY_LICENSES.csv`). The image also contains the `git` program
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
