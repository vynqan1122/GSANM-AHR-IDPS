#!/bin/sh
set -eu

: "${REDIS_PASSWORD:?REDIS_PASSWORD is required}"

case "$REDIS_PASSWORD" in
    *[!A-Za-z0-9._~-]*)
        echo "REDIS_PASSWORD contains unsupported characters" >&2
        exit 1
        ;;
esac

runtime_config=/tmp/ahr-redis.conf
umask 077
cp /opt/ahr-idps/redis.conf "$runtime_config"
printf '\nrequirepass %s\n' "$REDIS_PASSWORD" >> "$runtime_config"
chown redis:redis "$runtime_config"
chown -R redis:redis /data

exec /usr/local/bin/docker-entrypoint.sh redis-server "$runtime_config"
