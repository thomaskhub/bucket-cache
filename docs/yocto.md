# Yocto integration guide

Builds read sstate and download tarballs through the proxy with one
short-lived token per build. The build host needs no S3 credentials or tools:
BitBake fetches everything over plain HTTP(S) from `/t/<token>/<bucket>/<path>`.

In the examples, `cache.example.lan:8080` is the data listener and
`cache.example.lan:8081` the admin listener. `sstate` and `downloads` are
bucket aliases from the proxy config.

## 1. Get a token in CI

Create an API key with the `token-issuer` role once (in the UI or with
`POST /api/v1/apikeys`) and store it as a CI secret, `PROXY_ISSUER_KEY` below.
Each job then creates its own token, checks it, and revokes it at the end:

```sh
PROXY=http://cache.example.lan:8080
ADMIN=http://cache.example.lan:8081

export SSTATE_PROXY_TOKEN=$(curl -fsS -X POST "$ADMIN/api/v1/tokens" \
  -H "Authorization: Bearer $PROXY_ISSUER_KEY" -H "Content-Type: application/json" \
  -d '{"buckets":["sstate","downloads"],"ttl":"6h","description":"'"$CI_JOB_URL"'"}' | jq -r .token)
export BB_ENV_PASSTHROUGH_ADDITIONS="$BB_ENV_PASSTHROUGH_ADDITIONS SSTATE_PROXY_TOKEN"
trap 'curl -fsS -X DELETE -H "Authorization: Bearer $SSTATE_PROXY_TOKEN" "$ADMIN/api/v1/tokens/self"' EXIT

# Pre-flight: fail now if the token is wrong, instead of silently rebuilding everything.
code=$(curl -s -o /dev/null -w '%{http_code}' -I "$PROXY/t/$SSTATE_PROXY_TOKEN/sstate/preflight-check")
[ "$code" = 200 ] || [ "$code" = 404 ] || { echo "proxy token rejected ($code)"; exit 1; }

bitbake core-image-minimal
```

The token is only valid for the buckets it names and expires after the TTL
even if the job is killed before the `trap` runs.

On releases before Kirkstone, use `BB_ENV_EXTRAWHITE` instead of
`BB_ENV_PASSTHROUGH_ADDITIONS`.

## 2. `local.conf` or `site.conf`

```bitbake
PROXY = "http://cache.example.lan:8080/t/${SSTATE_PROXY_TOKEN}"

SSTATE_MIRRORS ?= "file://.* ${PROXY}/sstate/PATH;downloadfilename=PATH"

PREMIRRORS:prepend = "\
    git://.*/.*   ${PROXY}/downloads/ \
    gitsm://.*/.* ${PROXY}/downloads/ \
    ftp://.*/.*   ${PROXY}/downloads/ \
    http://.*/.*  ${PROXY}/downloads/ \
    https://.*/.* ${PROXY}/downloads/ \
"
# Optional: only use the mirror (reproducible, offline-like builds)
# BB_FETCH_PREMIRRORONLY = "1"

# Keep the per-build token out of the task signatures, so a new token
# doesn't invalidate sstate.
BB_BASEHASH_IGNORE_VARS:append = " SSTATE_PROXY_TOKEN PROXY"
```

(Before Kirkstone the last variable is `BB_HASHBASE_WHITELIST`.)

A missing sstate object returns `404`, and BitBake builds that task locally.
An expired or revoked token returns `401`, which is why the pre-flight check
above matters: without it, BitBake would treat every object as missing.

## 3. Filling the buckets

The proxy only reads. A trusted CI job (for example a nightly build on the main
branch) uploads with its own write credentials:

```bitbake
# in that job's local.conf: also keep git sources as tarballs for the premirror
BB_GENERATE_MIRROR_TARBALLS = "1"
```

```sh
aws s3 sync --endpoint-url "$S3_ENDPOINT" build/sstate-cache s3://yocto-sstate
aws s3 sync --endpoint-url "$S3_ENDPOINT" --exclude '*.done' --exclude '*.lock' --exclude 'git2/*' \
  build/downloads s3://yocto-downloads
```

`rclone sync` works the same way. Don't upload from untrusted jobs (pull
requests from forks): anything in the bucket is used by every build.

## 4. Checking that it works

- The `Sstate summary` line at the end of a build shows `Mirrors N` for tasks
  restored through the proxy.
- `yproxy_s3_requests_total` on `/metrics` counts requests per bucket and
  status.
- In cache mode, responses carry `X-Cache: HIT`, `MISS` or `STALE`.

The repository's `yocto-e2e` workflow (`test/yocto/e2e.sh`) runs this whole
setup against RustFS and checks that a second build with a new token restores
every task, with identical task hashes.
