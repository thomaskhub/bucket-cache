# yocto-cache-proxy

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
- CI: vet, race tests, lint, license check and a multi-arch image build.

Object access, tokens, caching, the UI and the git mirror follow in stages M1–M6.

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

## Licenses

The proxy is licensed under the Apache License 2.0 (see `LICENSE` and `NOTICE`). Every Go dependency must be MIT, BSD, ISC or
Apache-2.0; CI enforces this with `go-licenses` (see
`THIRD_PARTY_LICENSES.csv`). The image also contains the `git` program
(GPL-2.0), which runs as a separate process and is not linked into the proxy;
its license is in `/usr/share/doc/git` inside the image.
