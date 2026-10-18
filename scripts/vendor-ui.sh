#!/usr/bin/env bash
# Fetches the pinned third-party UI assets and rebuilds the stylesheet.
# The results are committed, so building yproxy needs neither this script
# nor network access (FR-63).
#
#   scripts/vendor-ui.sh          fetch Alpine.js and rebuild the CSS
#   scripts/vendor-ui.sh alpine   fetch Alpine.js (CSP build) and its licenses
#   scripts/vendor-ui.sh css      rebuild internal/ui/static/css/app.css
#
# Run "css" after using Tailwind classes that aren't in app.css yet.
set -euo pipefail

ALPINE_VERSION=3.17.4      # @alpinejs/csp, MIT
VUE_REACTIVITY_VERSION=3.5.40 # bundled inside Alpine, MIT
TAILWIND_VERSION=4.3.3     # tailwindcss standalone CLI, MIT (build tool only; its output is MIT too)

cd "$(dirname "$0")/.."
UI=internal/ui
VENDOR=$UI/static/vendor
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

alpine() {
  fetch "https://registry.npmjs.org/@alpinejs/csp/-/csp-$ALPINE_VERSION.tgz" "$TMP/alpine.tgz"
  tar -xzf "$TMP/alpine.tgz" -C "$TMP"
  cp "$TMP/package/dist/cdn.min.js" "$VENDOR/alpine-csp.min.js"
  # The npm package has no license file; take it from the tagged source.
  # Saved as .txt: .dockerignore drops *.md from the image build context.
  fetch "https://raw.githubusercontent.com/alpinejs/alpine/v$ALPINE_VERSION/LICENSE.md" "$VENDOR/LICENSE-alpinejs.txt"
  fetch "https://raw.githubusercontent.com/vuejs/core/v$VUE_REACTIVITY_VERSION/LICENSE" "$VENDOR/LICENSE-vue-reactivity.txt"
  echo "alpine $ALPINE_VERSION -> $VENDOR/alpine-csp.min.js"
}

css() {
  local os arch
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=macos ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported CPU" >&2; exit 1 ;; esac
  local bin=${TAILWIND_BIN:-}
  if [ -z "$bin" ]; then
    bin=$TMP/tailwindcss
    fetch "https://github.com/tailwindlabs/tailwindcss/releases/download/v$TAILWIND_VERSION/tailwindcss-$os-$arch" "$bin"
    chmod +x "$bin"
  fi
  "$bin" -i "$UI/tailwind/input.css" -o "$UI/static/css/app.css" --minify
  fetch "https://raw.githubusercontent.com/tailwindlabs/tailwindcss/v$TAILWIND_VERSION/LICENSE" "$VENDOR/LICENSE-tailwindcss.txt"
  echo "tailwind $TAILWIND_VERSION -> $UI/static/css/app.css"
}

case "${1:-all}" in
  alpine) alpine ;;
  css) css ;;
  all) alpine; css ;;
  *) echo "usage: $0 [alpine|css]" >&2; exit 2 ;;
esac
