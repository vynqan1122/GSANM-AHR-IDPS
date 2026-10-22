param([switch]$Install)
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if($Install) {
  python scripts/install_model_bundle.py
  if($LASTEXITCODE -ne 0){throw 'Bundle validation/install failed. Existing models were preserved.'}
}
if(-not (Test-Path 'experiments/bundles/colab-v2/manifest.json')){throw 'Run python scripts/install_model_bundle.py first.'}
$ca=@('--env-file','.env')
foreach($f in 'docker-compose.yml','sensors/suricata/compose.fragment.yml','sensors/falco/compose.fragment.yml','sensors/wazuh/compose.fragment.yml','pipeline/compose.fragment.yml','app/compose.fragment.yml','ai/compose.fragment.yml','ai/compose.bundle.yml'){$ca+=@('-f',$f)}
docker compose @ca config --quiet
if($LASTEXITCODE -ne 0){throw 'Compose validation failed'}
docker compose @ca build ai-bundle incident-engine
if($LASTEXITCODE -ne 0){throw 'AI build failed; old AI services were not stopped'}
docker compose @ca stop ai-network ai-log graph-builder fusion-engine
if($LASTEXITCODE -ne 0){throw 'Could not stop overlapping legacy scorers'}
$project=(docker compose @ca config --format json | ConvertFrom-Json).name
if($LASTEXITCODE -ne 0 -or -not $project){throw 'Cannot resolve Compose project'}
$bridge=docker ps -q --filter 'label=com.docker.compose.service=colab-bridge' --filter "label=com.docker.compose.project=$project"
if($bridge){docker stop $bridge; if($LASTEXITCODE -ne 0){throw 'Could not stop overlapping Colab bridge'}}
docker compose @ca up -d --no-build --no-deps --wait --wait-timeout 180 ai-bundle incident-engine rule-generator response-engine
if($LASTEXITCODE -ne 0){throw 'Bundle AI unhealthy; inspect logs. Pending events are preserved.'}
docker compose @ca ps ai-bundle incident-engine rule-generator response-engine
