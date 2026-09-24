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

foreach ($module in 'ai.network.train_xgboost', 'ai.logs.train', 'ai.graph.train', 'ai.fusion.train') {
  docker compose @composeArgs run --rm --no-deps ai-network python -m $module
  if ($LASTEXITCODE -ne 0) { throw "Model training failed: $module" }
}

Write-Output 'All models were trained and registered. Run scripts/start_ai.ps1 to start realtime inference.'
