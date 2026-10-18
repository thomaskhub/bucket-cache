#!/usr/bin/env bash
# Starts a local debug instance: yproxy with debug logging, a RustFS bucket
# with a test object, and a build token. Everything listens on localhost only.
# Uses Podman (podman-compose) by default, or Docker if Podman isn't installed;
# set CONTAINER_ENGINE=docker to force Docker.
#
#   scripts/debug.sh [up]    build and start, then print a token and examples
#   scripts/debug.sh token   create another token
#   scripts/debug.sh logs    follow the proxy logs
#   scripts/debug.sh down    stop (add --wipe to delete all data)
#
# Ports can be changed with DATA_PORT, ADMIN_PORT and RUSTFS_PORT.
set -euo pipefail

cd "$(dirname "$0")/../deploy/debug"
export DATA_PORT=${DATA_PORT:-8080} ADMIN_PORT=${ADMIN_PORT:-8081} RUSTFS_PORT=${RUSTFS_PORT:-9000}
BUCKET=debug-sstate

ENGINE=${CONTAINER_ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}
compose() {
  if [ "$ENGINE" = podman ] && command -v podman-compose >/dev/null; then
    podman-compose -p yproxy-debug -f compose.yml "$@"
  else
    "$ENGINE" compose -p yproxy-debug -f compose.yml "$@"
  fi
}

wait_for() { # url, name
  for _ in $(seq 60); do curl -fs -o /dev/null "$1" && return 0; sleep 1; done
  echo "$2 did not come up; see: $0 logs" >&2
  exit 1
}

make_secrets() {
  mkdir -p secrets
  [ -s secrets/admin_api_key ] || openssl rand -hex 32 > secrets/admin_api_key
  [ -s secrets/db_encryption_key ] || openssl rand -hex 32 > secrets/db_encryption_key
  [ -s secrets/initial_admin_user ] || printf admin > secrets/initial_admin_user
  [ -s secrets/initial_admin_password ] || openssl rand -hex 12 > secrets/initial_admin_password
  printf debug-access-key > secrets/rustfs_access_key
  printf debug-secret-key > secrets/rustfs_secret_key
  chmod 644 secrets/*   # the proxy runs as uid 10001 and must read them
  chmod 755 secrets
}

s3() { # method, path, [curl args...]
  local m=$1 p=$2; shift 2
  curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user debug-access-key:debug-secret-key \
    -X "$m" "http://127.0.0.1:$RUSTFS_PORT/$p" "$@"
}

seed_bucket() {
  wait_for "http://127.0.0.1:$RUSTFS_PORT/health" RustFS || true
  # RustFS can answer /health shortly before it accepts writes, so retry.
  for _ in $(seq 30); do
    s3 PUT "$BUCKET" -o /dev/null 2>/dev/null || true   # already exists is fine
    echo "hello from the debug bucket" | s3 PUT "$BUCKET/hello.txt" --data-binary @- -o /dev/null 2>/dev/null && return 0
    sleep 1
  done
  echo "could not create the test bucket in RustFS; see: $0 logs" >&2
  exit 1
}

new_token() {
  curl -fsS -X POST "http://127.0.0.1:$ADMIN_PORT/api/v1/tokens" \
    -H "Authorization: Bearer $(cat secrets/admin_api_key)" \
    -d '{"buckets":["sstate"],"ttl":"12h","description":"debug"}' |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

print_usage() {
  local t=$1
  cat <<MSG

Debug instance is running.
  data:   http://localhost:$DATA_PORT
  admin:  http://localhost:$ADMIN_PORT  (key in deploy/debug/secrets/admin_api_key)
  web UI: http://localhost:$ADMIN_PORT/
          user $(cat secrets/initial_admin_user), initial password $(cat secrets/initial_admin_password)
          (first login: leave the code empty, set up TOTP, then choose a new password;
          the initial password stops working once changed)
  rustfs: http://localhost:$RUSTFS_PORT  (debug-access-key / debug-secret-key)

Token (12h): $t

Try it:
  curl http://localhost:$DATA_PORT/t/$t/sstate/hello.txt
  curl -I http://localhost:$DATA_PORT/t/$t/sstate/missing   # 404

BitBake (local.conf):
  SSTATE_MIRRORS ?= "file://.* http://localhost:$DATA_PORT/t/$t/sstate/PATH;downloadfilename=PATH"

Logs: $0 logs    Stop: $0 down
MSG
}

case "${1:-up}" in
  up)
    command -v "$ENGINE" >/dev/null || { echo "podman (or docker) is required" >&2; exit 1; }
    make_secrets
    compose up -d --build
    seed_bucket
    wait_for "http://127.0.0.1:$ADMIN_PORT/healthz" yproxy
    print_usage "$(new_token)"
    ;;
  token) new_token ;;
  logs)  compose logs -f yproxy ;;
  down)
    if [ "${2:-}" = --wipe ]; then compose down -v; rm -rf secrets; else compose down; fi
    ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
