#!/bin/sh
set -eu

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${AHR_DB_USER:?AHR_DB_USER is required}"
: "${AHR_DB_PASSWORD:?AHR_DB_PASSWORD is required}"

case "$AHR_DB_USER" in
    ''|*[!A-Za-z0-9_]*)
        echo "AHR_DB_USER must contain only letters, digits, and underscores" >&2
        exit 1
        ;;
esac

psql \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set=ON_ERROR_STOP=1 \
    --set=app_user="$AHR_DB_USER" \
    --set=app_password="$AHR_DB_PASSWORD" \
    --set=database_name="$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'app_user',
    :'app_password'
)
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', :'app_user')
\gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

SELECT format('CREATE SCHEMA IF NOT EXISTS ahr AUTHORIZATION %I', :'app_user')
\gexec

SELECT format('ALTER SCHEMA ahr OWNER TO %I', :'app_user')
\gexec

SELECT format('ALTER ROLE %I SET search_path TO ahr, public', :'app_user')
\gexec

SELECT format('GRANT USAGE, CREATE ON SCHEMA ahr TO %I', :'app_user')
\gexec
SQL
