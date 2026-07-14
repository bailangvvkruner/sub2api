#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_VERSION="${SUB2API_BUILD_VERSION:-development}"

docker build \
    --build-arg "SUB2API_BUILD_VERSION=${BUILD_VERSION}" \
    -t "${SUB2API_IMAGE:-sub2api:latest}" \
    -f "${REPO_ROOT}/Dockerfile" \
    "${REPO_ROOT}"
