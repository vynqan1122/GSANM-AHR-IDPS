$ErrorActionPreference = 'Stop'

$files = @(
  'docker-compose.yml',
  'sensors/suricata/compose.fragment.yml',
  'sensors/falco/compose.fragment.yml',
  'sensors/wazuh/compose.fragment.yml',
  'pipeline/compose.fragment.yml',
  'app/compose.fragment.yml',
  'ai/compose.fragment.yml'
)
$composeArgs = @('--env-file', '.env')
foreach ($file in $files) { $composeArgs += @('-f', $file) }

docker compose @composeArgs config --quiet
$sql = Get-Content -Raw .\scripts\register_existing_models.sql
$sql | docker compose @composeArgs exec -T postgres sh -ec 'PGPASSWORD="$AHR_DB_PASSWORD" psql --host=127.0.0.1 --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" --set=ON_ERROR_STOP=1'
docker compose @composeArgs up -d --wait --wait-timeout 300 --no-build --no-deps `
  ai-network ai-log graph-builder fusion-engine incident-engine rule-generator response-engine
docker compose @composeArgs ps ai-network ai-log graph-builder fusion-engine incident-engine rule-generator response-engine
