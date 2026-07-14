#!/bin/sh
set -eu

# The supported installer is the Rust/PostgreSQL Docker deployment. This
# compatibility entry point keeps existing curl commands working.
case "${1:-install}" in
    install|upgrade) ;;
    -h|--help|help)
        echo "Usage: $0 [install|upgrade]"
        echo "Installs the Rust backend and PostgreSQL with Docker Compose."
        exit 0
        ;;
    *)
        echo "Unsupported command: $1" >&2
        echo "Use Docker Compose directly for stop, backup, restore, or removal." >&2
        exit 2
        ;;
esac

if [ "${0#*/}" != "$0" ]; then
    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
    if [ -f "${SCRIPT_DIR}/docker-deploy.sh" ]; then
        exec sh "${SCRIPT_DIR}/docker-deploy.sh"
    fi
fi

BRANCH="${SUB2API_RUST_BRANCH:-main}"
URL="${SUB2API_INSTALL_URL:-https://raw.githubusercontent.com/bailangvvkruner/sub2api/${BRANCH}/deploy/docker-deploy.sh}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${URL}" | SUB2API_RUST_BRANCH="${BRANCH}" sh
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${URL}" | SUB2API_RUST_BRANCH="${BRANCH}" sh
else
    echo "curl or wget is required" >&2
    exit 1
fi
