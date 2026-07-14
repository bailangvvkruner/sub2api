#!/bin/sh
set -eu

# Rust is the only supported production backend. A prepared deployment keeps
# both scripts together; stdin installs fall back to downloading the Rust entry.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)"
if [ -f "${SCRIPT_DIR}/docker-deploy-rust.sh" ]; then
    exec sh "${SCRIPT_DIR}/docker-deploy-rust.sh" "$@"
fi

RUST_BRANCH="${SUB2API_RUST_BRANCH:-main}"
SCRIPT_URL="${SUB2API_RUST_DEPLOY_URL:-https://raw.githubusercontent.com/bailangvvkruner/sub2api/${RUST_BRANCH}/deploy/docker-deploy-rust.sh}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${SCRIPT_URL}" | SUB2API_RUST_BRANCH="${RUST_BRANCH}" sh
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${SCRIPT_URL}" | SUB2API_RUST_BRANCH="${RUST_BRANCH}" sh
else
    echo "curl or wget is required" >&2
    exit 1
fi
