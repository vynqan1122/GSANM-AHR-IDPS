#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
secret_dir="$PROJECT_ROOT/sensors/wazuh/secrets"
secret_file="$secret_dir/authd.pass"

mkdir -p "$secret_dir"
umask 077

if [[ -s "$secret_file" ]]; then
    chmod 600 "$secret_file" 2>/dev/null || true
    secret_length="$(wc -c < "$secret_file" | tr -d '[:space:]')"
    line_count="$(wc -l < "$secret_file" | tr -d '[:space:]')"
    [[ "$line_count" == 1 && "$secret_length" == 49 ]] || {
        printf '[FAIL] Existing Wazuh enrollment secret has an invalid format; refusing to replace it automatically\n' >&2
        exit 1
    }
    LC_ALL=C grep -Eq '^[A-Fa-f0-9]{48}$' "$secret_file" || {
        printf '[FAIL] Existing Wazuh enrollment secret must be one 48-character hexadecimal value\n' >&2
        exit 1
    }
    printf '[PASS] Wazuh enrollment secret already exists (value not printed)\n'
    exit 0
fi

if command -v openssl >/dev/null 2>&1; then
    secret="$(openssl rand -hex 24)"
elif [[ -r /dev/urandom ]] && command -v od >/dev/null 2>&1; then
    secret="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
else
    printf '[FAIL] openssl or /dev/urandom plus od is required\n' >&2
    exit 1
fi

printf '%s\n' "$secret" >"$secret_file"
chmod 600 "$secret_file" 2>/dev/null || true
printf '[PASS] Created private Wazuh enrollment secret (value not printed)\n'
