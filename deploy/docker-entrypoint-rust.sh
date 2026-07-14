#!/bin/sh
set -eu

umask 027

if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/data
    chown -R sub2api:sub2api -- /app/data
    command -v gosu >/dev/null 2>&1 || {
        echo "gosu is required to drop root privileges" >&2
        exit 1
    }
    exec gosu sub2api "$@"
fi

exec "$@"
