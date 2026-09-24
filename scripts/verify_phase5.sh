#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/app.sh
source "$SCRIPT_DIR/lib/app.sh"

pass() {
    printf '[PASS] %s\n' "$*"
}

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

mode=runtime
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help)
        printf 'Usage: ./scripts/verify_phase5.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_app_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"

for script in "$SCRIPT_DIR/verify_phase5.sh"; do
    bash -n "$script"
done

for file in \
    dataset_collection/cli.py \
    dataset_collection/guard.py \
    dataset_collection/traffic.py \
    dataset_collection/exporter.py \
    normalizer/migrations/002_phase5_dataset_collection.sql; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 5 file: $file"
done

effective="$(ahr_app_compose config)"
ahr_app_compose config --quiet
backend_section="$(ahr_compose_service_section backend <<<"$effective")"
grep -Fq 'target: /opt/ahr-idps/datasets' <<<"$backend_section" || \
    fail 'backend must mount the dataset export directory'
grep -Fq 'type: bind' <<<"$backend_section" || \
    fail 'dataset export directory must be a host bind mount'
grep -Fq 'pyarrow' "$AHR_PROJECT_ROOT/backend/requirements.txt" || \
    fail 'backend image must include Parquet export support'

pass 'Phase 5 static dataset framework, migration, allowlist guard, and export contract are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 5 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine
ahr_require_phase4_ready=no
if ! ahr_app_compose ps -q backend >/dev/null 2>&1; then
    ahr_require_phase4_ready=yes
fi

# Rebuild the shared pipeline image so migration 002 is present, then force
# the normalizer to restart and apply it. This is a schema gate, not traffic.
ahr_app_compose build collector
ahr_app_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps normalizer

bash "$SCRIPT_DIR/start_app.sh"

ahr_app_compose exec -T backend python -m pytest -q -p no:cacheprovider \
    backend/tests dataset_collection/tests
pass 'Dataset framework unit tests passed'

if ahr_app_compose exec -T backend python -m dataset_collection.cli \
    --target https://example.com run-benign --fast >/tmp/ahr_phase5_external.out 2>&1; then
    fail 'external target was accepted'
fi
grep -q '^ABORT:' /tmp/ahr_phase5_external.out || \
    fail 'external target rejection did not explain ABORT'
pass 'External target is rejected before any traffic is generated'

run_id="ahr_p5_$(date +%s)_$$_${RANDOM:-0}"
benign_id="${run_id}_benign"
attack_id="${run_id}_sqli"
scan_id="${run_id}_scan"

ahr_app_compose exec -T backend python -m dataset_collection.cli \
    --target http://nginx run-benign \
    --scenario-id "$benign_id" --repeat 1 --fast --notes phase5-acceptance
ahr_app_compose exec -T backend python -m dataset_collection.cli \
    --target http://nginx run-controlled sql_injection \
    --scenario-id "$attack_id" --repeat 1 --fast --notes phase5-acceptance
ahr_app_compose exec -T backend python -m dataset_collection.cli \
    --target http://nginx run-controlled scanner_pattern \
    --scenario-id "$scan_id" --repeat 1 --fast --notes phase5-acceptance

postgres_count() {
    local query="$1"
    ahr_app_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql \
          --host=127.0.0.1 \
          --username="$AHR_DB_USER" \
          --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="$1"
    ' sh "$query" | tr -d '\r[:space:]'
}

scenario_count="$(postgres_count "SELECT count(*) FROM ahr.scenario_runs WHERE scenario_id IN ('$benign_id','$attack_id','$scan_id');")"
[[ "$scenario_count" == 3 ]] || fail "Expected 3 scenario_runs, got $scenario_count"

label_count="$(postgres_count "SELECT count(*) FROM ahr.event_labels WHERE scenario_id IN ('$benign_id','$attack_id','$scan_id');")"
[[ "$label_count" =~ ^[0-9]+$ ]] && (( label_count > 0 )) || \
    fail 'No events were linked to Phase 5 scenarios'

benign_labels="$(postgres_count "SELECT count(*) FROM ahr.event_labels WHERE scenario_id = '$benign_id' AND label = 'benign';")"
attack_labels="$(postgres_count "SELECT count(*) FROM ahr.event_labels WHERE scenario_id IN ('$attack_id','$scan_id') AND label = 'attack';")"
[[ "$benign_labels" =~ ^[0-9]+$ ]] && (( benign_labels > 0 )) || fail 'Benign labels were not stored'
[[ "$attack_labels" =~ ^[0-9]+$ ]] && (( attack_labels > 0 )) || fail 'Controlled attack labels were not stored'
pass 'Benign and controlled scenario labels are stored and linked to real events'

ahr_app_compose exec -T backend python -m dataset_collection.cli export \
    >/tmp/ahr_phase5_export.out
ahr_app_compose exec -T backend sh -ec '
    test -s /opt/ahr-idps/datasets/raw/events.jsonl &&
    test -s /opt/ahr-idps/datasets/normalized/events.jsonl &&
    test -s /opt/ahr-idps/datasets/network/flows.jsonl &&
    test -s /opt/ahr-idps/datasets/logs/events.jsonl &&
    test -s /opt/ahr-idps/datasets/labels/event_labels.csv &&
    test -s /opt/ahr-idps/datasets/metadata/scenario_runs.csv &&
    test -s /opt/ahr-idps/datasets/metadata/splits.csv &&
    test -s /opt/ahr-idps/datasets/processed/events.parquet &&
    test -s /opt/ahr-idps/datasets/graphs/events_graph.pt &&
    test -s /opt/ahr-idps/datasets/metadata/manifest.json
'
pass 'Dataset export wrote JSONL, CSV metadata/labels/splits, Parquet, and graph artifact'

bash "$SCRIPT_DIR/verify_phase4.sh"
pass 'Phase 5 runtime acceptance PASS: dataset collection, controlled lab scenarios, labels, export, and target guard verified'
