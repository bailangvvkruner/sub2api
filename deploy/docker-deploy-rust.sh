#!/bin/sh
set -eu

REPOSITORY_URL="${SUB2API_REPOSITORY_URL:-https://github.com/bailangvvkruner/sub2api.git}"
RUST_BRANCH="${SUB2API_RUST_BRANCH:-main}"
RUST_REF="${SUB2API_RUST_REF:-}"
SOURCE_DIR="${SUB2API_SOURCE_DIR:-.source}"
POSTGRES_MAJOR=18

command -v git >/dev/null 2>&1 || {
    echo "git is required" >&2
    exit 1
}
command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required" >&2
    exit 1
}

COMPOSE_VARIANT=''
COMPOSE_DISPLAY=''
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_VARIANT=v2
    COMPOSE_DISPLAY='docker compose'
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
    COMPOSE_VARIANT=v1
    COMPOSE_DISPLAY='docker-compose'
else
    echo "Docker Compose v2 (docker compose) or v1 (docker-compose) is required" >&2
    exit 1
fi

compose() {
    if [ "${COMPOSE_VARIANT}" = v2 ]; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

if [ -n "${RUST_REF}" ] && ! printf '%s' "${RUST_REF}" | grep -Eq '^[[:xdigit:]]{40}$'; then
    echo "SUB2API_RUST_REF must be a full 40-character Git revision" >&2
    exit 1
fi

if [ ! -d "${SOURCE_DIR}/.git" ]; then
    git clone --depth 1 --branch "${RUST_BRANCH}" "${REPOSITORY_URL}" "${SOURCE_DIR}"
fi
if [ -n "${RUST_REF}" ]; then
    git -C "${SOURCE_DIR}" fetch --depth 1 origin "${RUST_REF}"
    git -C "${SOURCE_DIR}" checkout --detach FETCH_HEAD
else
    git -C "${SOURCE_DIR}" fetch --depth 1 origin "${RUST_BRANCH}"
    git -C "${SOURCE_DIR}" checkout -B "${RUST_BRANCH}" FETCH_HEAD
fi
SOURCE_REVISION="$(git -C "${SOURCE_DIR}" rev-parse HEAD)"

if [ -e data ] && [ ! -d data ]; then
    echo "data exists but is not a directory" >&2
    exit 1
fi
if [ -e postgres_data ] && [ ! -d postgres_data ]; then
    echo "postgres_data exists but is not a directory" >&2
    exit 1
fi
if [ -L .env ]; then
    echo ".env must be a regular file, not a symbolic link" >&2
    exit 1
fi

EXISTING_POSTGRES=false
if [ -d postgres_data ]; then
    if [ -f postgres_data/PG_VERSION ]; then
        PG_VERSION="$(tr -d '[:space:]' <postgres_data/PG_VERSION)"
        if [ "${PG_VERSION}" != "${POSTGRES_MAJOR}" ]; then
            echo "postgres_data is PostgreSQL ${PG_VERSION:-unknown}; this deployment requires PostgreSQL ${POSTGRES_MAJOR}" >&2
            echo "Run pg_upgrade or restore a logical dump into a fresh postgres_data directory" >&2
            exit 1
        fi
        EXISTING_POSTGRES=true
    elif [ -n "$(find postgres_data -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "postgres_data is non-empty but has no PG_VERSION; refusing to initialize over it" >&2
        exit 1
    fi
fi

if [ "${EXISTING_POSTGRES}" = true ] && [ ! -f .env ]; then
    echo "postgres_data already exists; restore the matching .env before deployment" >&2
    exit 1
fi

mkdir -p data postgres_data

if [ -f .env ]; then
    chmod 600 .env
fi

if [ ! -f .env ]; then
    umask 077
    POSTGRES_PASSWORD="$(openssl rand -hex 32)"
    JWT_SECRET="$(openssl rand -hex 32)"
    TOTP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
    cat >.env <<EOF
SUB2API_SOURCE_DIR=${SOURCE_DIR}
SUB2API_RUST_BRANCH=${RUST_BRANCH}
SUB2API_BUILD_VERSION=${SOURCE_REVISION}
SUB2API_RUST_ROLLBACK_REFS=
POSTGRES_USER=sub2api
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=sub2api
JWT_SECRET=${JWT_SECRET}
TOTP_ENCRYPTION_KEY=${TOTP_ENCRYPTION_KEY}
ADMIN_EMAIL=admin@sub2api.local
ADMIN_PASSWORD=
SERVER_PORT=8080
TZ=Asia/Shanghai
EOF
    chmod 600 .env
    echo "Generated PostgreSQL, JWT, and TOTP secrets in .env"
else
    echo "Keeping existing .env"
fi

umask 077

env_value() {
    sed -n "s/^${1}=//p" .env | tail -n 1 | tr -d '\r'
}

env_has_value() {
    [ -n "$(env_value "$1")" ]
}

set_env_value() {
    key="$1"
    value="$2"
    temporary=".env.tmp.$$"
    rm -f "${temporary}"
    if awk -v wanted="${key}" -v replacement="${key}=${value}" '
        BEGIN { found = 0 }
        index($0, wanted "=") == 1 {
            if (!found) print replacement
            found = 1
            next
        }
        { print }
        END { if (!found) print replacement }
    ' .env >"${temporary}"; then
        chmod 600 "${temporary}"
        mv "${temporary}" .env
    else
        rm -f "${temporary}"
        return 1
    fi
}

ensure_env_value() {
    key="$1"
    value="$2"
    if ! env_has_value "${key}"; then
        set_env_value "${key}" "${value}"
        echo "Added ${key} to .env"
    fi
}

ensure_env_key() {
    key="$1"
    value="$2"
    if ! grep -q "^${key}=" .env; then
        printf '%s=%s\n' "${key}" "${value}" >>.env
    fi
}

ensure_generated_secret() {
    key="$1"
    if ! env_has_value "${key}"; then
        set_env_value "${key}" "$(openssl rand -hex 32)"
        echo "Added ${key} to .env"
    fi
}

valid_totp_key() {
    value="$(env_value TOTP_ENCRYPTION_KEY)"
    [ "${#value}" -eq 64 ] && printf '%s' "${value}" | grep -Eq '^[[:xdigit:]]{64}$'
}

valid_revision() {
    [ "${#1}" -eq 40 ] && printf '%s' "$1" | grep -Eq '^[[:xdigit:]]{40}$'
}

record_rollback_revision() {
    previous="$1"
    current="$2"
    existing="$(env_value SUB2API_RUST_ROLLBACK_REFS)"
    candidates="${previous} $(printf '%s' "${existing}" | tr ',' ' ')"
    revisions=''
    count=0
    for candidate in ${candidates}; do
        if ! valid_revision "${candidate}" || [ "${candidate}" = "${current}" ]; then
            continue
        fi
        case ",${revisions}," in
            *,"${candidate}",*) continue ;;
        esac
        if [ -n "${revisions}" ]; then
            revisions="${revisions},${candidate}"
        else
            revisions="${candidate}"
        fi
        count=$((count + 1))
        [ "${count}" -ge 3 ] && break
    done
    set_env_value SUB2API_RUST_ROLLBACK_REFS "${revisions}"
}

if [ "${EXISTING_POSTGRES}" = "true" ]; then
    for key in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB JWT_SECRET; do
        if ! env_has_value "${key}"; then
            echo "postgres_data already exists; ${key} must be restored in .env" >&2
            exit 1
        fi
    done
    if ! valid_totp_key; then
        echo "postgres_data already exists; restore its 64-hex-character TOTP_ENCRYPTION_KEY" >&2
        exit 1
    fi
fi

# Existing deployments can reuse their .env. Fill only the Rust deployment
# contract that is missing, while preserving every non-empty existing value.
set_env_value SUB2API_SOURCE_DIR "${SOURCE_DIR}"
PREVIOUS_BUILD_VERSION="$(env_value SUB2API_BUILD_VERSION)"
set_env_value SUB2API_RUST_BRANCH "${RUST_BRANCH}"
ensure_env_key SUB2API_RUST_ROLLBACK_REFS ''
record_rollback_revision "${PREVIOUS_BUILD_VERSION}" "${SOURCE_REVISION}"
set_env_value SUB2API_BUILD_VERSION "${SOURCE_REVISION}"
if [ "${EXISTING_POSTGRES}" = "false" ]; then
    ensure_env_value POSTGRES_USER sub2api
    ensure_generated_secret POSTGRES_PASSWORD
    ensure_env_value POSTGRES_DB sub2api
    ensure_generated_secret JWT_SECRET
    if ! valid_totp_key; then
        set_env_value TOTP_ENCRYPTION_KEY "$(openssl rand -hex 32)"
        echo "Added a valid persistent TOTP_ENCRYPTION_KEY to .env"
    fi
fi
ensure_env_value ADMIN_EMAIL admin@sub2api.local
ensure_env_key ADMIN_PASSWORD ''
ensure_env_value SERVER_PORT 8080
ensure_env_value TZ Asia/Shanghai
chmod 600 .env

COMPOSE_SOURCE="${SOURCE_DIR}/deploy/docker-compose.yml"
if [ ! -f "${COMPOSE_SOURCE}" ]; then
    echo "Compose file is missing from ${SOURCE_DIR}" >&2
    exit 1
fi
if [ -f docker-compose.yml ] && ! cmp -s "${COMPOSE_SOURCE}" docker-compose.yml; then
    if [ ! -f docker-compose.pre-rust.yml ]; then
        cp docker-compose.yml docker-compose.pre-rust.yml
        echo "Saved the previous Compose file as docker-compose.pre-rust.yml"
    fi
fi
cp "${COMPOSE_SOURCE}" "docker-compose.yml.tmp.$$"
chmod 644 "docker-compose.yml.tmp.$$"
mv "docker-compose.yml.tmp.$$" docker-compose.yml

for script in docker-deploy.sh docker-deploy-rust.sh; do
    source_script="${SOURCE_DIR}/deploy/${script}"
    if [ ! -f "${source_script}" ]; then
        echo "Deployment script is missing from ${SOURCE_DIR}: ${script}" >&2
        exit 1
    fi
    cp "${source_script}" "${script}.tmp.$$"
    chmod 755 "${script}.tmp.$$"
    mv "${script}.tmp.$$" "${script}"
done

if ! compose config >/dev/null; then
    echo "docker-compose.yml or .env failed Compose validation" >&2
    exit 1
fi

echo "Rust/PostgreSQL deployment prepared in $(pwd)"
echo "Start: DOCKER_BUILDKIT=1 ${COMPOSE_DISPLAY} up -d --build --remove-orphans"
echo "Admin password: ${COMPOSE_DISPLAY} logs sub2api | grep 'admin password'"
