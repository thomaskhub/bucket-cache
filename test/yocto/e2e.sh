#!/usr/bin/env bash
# Yocto end-to-end test (M2, YOC-1, YOC-2, acceptance 1, 2, 4).
#
# Builds a small native recipe twice through the proxy: build 1 fills a
# RustFS bucket with sstate and download tarballs, build 2 starts from empty
# SSTATE_DIR and DL_DIR with a different token and must restore every task
# from the proxy. The same task hashes with two tokens prove the token
# doesn't reach the signatures.
#
# Needs: a running RustFS (RUSTFS_ENDPOINT, RUSTFS_ACCESS_KEY,
# RUSTFS_SECRET_KEY), the aws CLI, the Yocto host packages, and a yproxy
# binary (YPROXY, default ./yproxy). Run from the repo root.
set -euo pipefail

: "${RUSTFS_ENDPOINT:?}" "${RUSTFS_ACCESS_KEY:?}" "${RUSTFS_SECRET_KEY:?}"
YPROXY=${YPROXY:-./yproxy}
POKY_REPO=${POKY_REPO:-https://github.com/yoctoproject/poky}
POKY_BRANCH=${POKY_BRANCH:-scarthgap}
TARGET=${TARGET:-quilt-native}
WORK=${WORK:-$PWD/.yocto-e2e}
DATA=http://127.0.0.1:18080
ADMIN=http://127.0.0.1:18081

log() { printf '\n=== %s\n' "$*"; }
# On GitHub Actions, results also go into annotations, which stay readable
# through the API when the raw logs aren't.
note() { echo "$*"; [ -z "${GITHUB_ACTIONS:-}" ] || echo "::notice title=yocto-e2e::$*"; }
fail() { echo "FAIL: $*" >&2; [ -z "${GITHUB_ACTIONS:-}" ] || echo "::error title=yocto-e2e::$*"; exit 1; }

mkdir -p "$WORK"/{secrets,data,cache,git}
WORK=$(cd "$WORK" && pwd)
export AWS_ACCESS_KEY_ID=$RUSTFS_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$RUSTFS_SECRET_KEY AWS_DEFAULT_REGION=us-east-1
s3() { aws --endpoint-url "$RUSTFS_ENDPOINT" s3 "$@"; }

log "Creating buckets"
s3 mb s3://e2e-sstate 2>/dev/null || true
s3 mb s3://e2e-downloads 2>/dev/null || true

log "Starting yproxy"
openssl rand -hex 32 > "$WORK/secrets/admin_api_key"
printf %s "$RUSTFS_ACCESS_KEY" > "$WORK/secrets/ak"
printf %s "$RUSTFS_SECRET_KEY" > "$WORK/secrets/sk"
cat > "$WORK/config.yaml" <<CFG
server: { data_listen: "127.0.0.1:18080", admin_listen: "127.0.0.1:18081", public_base_url: "$DATA" }
auth: { bootstrap_admin_key: { file: $WORK/secrets/admin_api_key } }
storage: { db_path: $WORK/data/proxy.db, cache_root: $WORK/cache }
buckets:
  - alias: sstate
    provider: rustfs
    endpoint: $RUSTFS_ENDPOINT
    bucket: e2e-sstate
    credentials: { access_key_id: { file: $WORK/secrets/ak }, secret_access_key: { file: $WORK/secrets/sk } }
  - alias: downloads
    provider: rustfs
    endpoint: $RUSTFS_ENDPOINT
    bucket: e2e-downloads
    credentials: { access_key_id: { file: $WORK/secrets/ak }, secret_access_key: { file: $WORK/secrets/sk } }
log: { level: info, access: true }
CFG
"$YPROXY" serve --config "$WORK/config.yaml" > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null || true' EXIT
for _ in $(seq 30); do curl -fs -o /dev/null "$ADMIN/healthz" && break; sleep 1; done
curl -fs -o /dev/null "$ADMIN/healthz" || { cat "$WORK/proxy.log"; fail "proxy did not start"; }

new_token() {
  curl -fsS -X POST "$ADMIN/api/v1/tokens" -H "Authorization: Bearer $(cat "$WORK/secrets/admin_api_key")" \
    -d '{"buckets":["sstate","downloads"],"ttl":"6h","description":"yocto e2e"}' | jq -r .token
}

log "Cloning poky $POKY_BRANCH"
[ -d "$WORK/poky" ] || git clone -q --depth 1 --branch "$POKY_BRANCH" "$POKY_REPO" "$WORK/poky"

# build <name> <token> <extra local.conf lines>
build() {
  local name=$1 token=$2 extra=$3 dir="$WORK/build-$1"
  rm -rf "$dir"
  pushd . > /dev/null
  # oe-init-build-env reads unset variables, so run it without -u.
  set +u
  # shellcheck disable=SC1091
  source "$WORK/poky/oe-init-build-env" "$dir" > /dev/null
  set -u
  cat >> conf/local.conf <<CONF
SSTATE_DIR = "$dir/sstate"
DL_DIR = "$dir/downloads"
PROXY = "$DATA/t/\${SSTATE_PROXY_TOKEN}"
SSTATE_MIRRORS ?= "file://.* \${PROXY}/sstate/PATH;downloadfilename=PATH"
PREMIRRORS:prepend = "\\
    git://.*/.*   \${PROXY}/downloads/ \\
    ftp://.*/.*   \${PROXY}/downloads/ \\
    http://.*/.*  \${PROXY}/downloads/ \\
    https://.*/.* \${PROXY}/downloads/ \\
"
BB_BASEHASH_IGNORE_VARS:append = " SSTATE_PROXY_TOKEN PROXY"
BB_GENERATE_MIRROR_TARBALLS = "1"
INHERIT:remove = "uninative"
$extra
CONF
  export SSTATE_PROXY_TOKEN=$token
  export BB_ENV_PASSTHROUGH_ADDITIONS="${BB_ENV_PASSTHROUGH_ADDITIONS:-} SSTATE_PROXY_TOKEN"
  bitbake "$TARGET" 2>&1 | tee "$WORK/$name.log"
  # Write signature data for every task; the file names carry the task hashes.
  bitbake -S none "$TARGET" > /dev/null
  find "$dir/tmp/stamps" -name '*.sigdata.*' -printf '%f\n' | sort > "$WORK/$name.sigs"
  [ -s "$WORK/$name.sigs" ] || fail "no signature data written for build $name"
  popd > /dev/null
}

TOKEN1=$(new_token)
log "Build 1: fill sstate from scratch"
build one "$TOKEN1" ""
s3 sync --only-show-errors "$WORK/build-one/sstate" s3://e2e-sstate
s3 sync --only-show-errors --exclude '*.done' --exclude '*.lock' --exclude 'git2/*' "$WORK/build-one/downloads" s3://e2e-downloads

log "Pre-flight check (FR-27)"
code=$(curl -s -o /dev/null -w '%{http_code}' -I "$DATA/t/$TOKEN1/sstate/preflight-check")
[ "$code" = 404 ] || fail "pre-flight with a good token returned $code, want 404"
curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN1" "$ADMIN/api/v1/tokens/self"
sleep 6 # validation cache is at most 5 s
code=$(curl -s -o /dev/null -w '%{http_code}' -I "$DATA/t/$TOKEN1/sstate/preflight-check")
[ "$code" = 401 ] || fail "pre-flight with a revoked token returned $code, want 401"

TOKEN2=$(new_token)
[ "$TOKEN1" != "$TOKEN2" ] || fail "tokens are equal"
log "Build 2: empty SSTATE_DIR and DL_DIR, new token, mirror only"
build two "$TOKEN2" 'BB_FETCH_PREMIRRORONLY = "1"'

log "Checking results"
note "build 1: $(grep -E 'Sstate summary|Tasks Summary' "$WORK/one.log" | tr '\n' ' ')"
summary=$(grep -E 'Sstate summary' "$WORK/two.log" | tail -1)
note "build 2: $summary $(grep -E 'Tasks Summary' "$WORK/two.log")"
note "task signatures: $(wc -l < "$WORK/one.sigs") identical between the two tokens"
echo "$summary" | grep -q 'Missed 0' || fail "build 2 missed sstate objects"
echo "$summary" | grep -qE 'Mirrors [1-9]' || fail "build 2 restored nothing from the mirror"
grep -q 'Running task.*do_compile' "$WORK/two.log" && fail "build 2 compiled something instead of restoring it"
diff -u "$WORK/one.sigs" "$WORK/two.sigs" > /dev/null || fail "task signatures differ between tokens"

# YOC-1: .siginfo files and the XX/YY/ layout went through the proxy.
grep -qE '"key":"([^"]*/)?[0-9a-f]{2}/[0-9a-f]{2}/sstate:' "$WORK/proxy.log" || fail "no XX/YY sstate paths in proxy log"
grep -q '\.siginfo"' "$WORK/proxy.log" || fail "no .siginfo requests in proxy log"
grep -q '"method":"HEAD"' "$WORK/proxy.log" || fail "no HEAD (checkstatus) requests in proxy log"
grep -q '"bucket":"downloads"' "$WORK/proxy.log" || echo "note: no download-tarball requests (sstate covered everything)"

# Acceptance 7: the token never appears in the logs.
for t in "$TOKEN1" "$TOKEN2"; do
  grep -qF "$t" "$WORK/proxy.log" && fail "token value found in proxy log"
done

note "proxy requests: $(grep -c '"msg":"request"' "$WORK/proxy.log") total, $(grep -c '"method":"HEAD"' "$WORK/proxy.log") HEAD, $(grep -c '"status":200' "$WORK/proxy.log") with 200, $(grep -c '"status":404' "$WORK/proxy.log") with 404"
log "PASS"
