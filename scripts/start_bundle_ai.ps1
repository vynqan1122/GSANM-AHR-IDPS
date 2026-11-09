param(
  [switch]$Install,
  [string]$BundleDir='experiments/bundles/dvwa-100k-20261022'
)
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

if([IO.Path]::IsPathRooted($BundleDir) -or $BundleDir -match '(^|[\\/])\.\.([\\/]|$)'){
  throw 'BundleDir must be a relative path inside the repository.'
}
$bundlePath=Join-Path (Get-Location) $BundleDir
if($Install) {
  python scripts/install_model_bundle.py --output $BundleDir
  if($LASTEXITCODE -ne 0){throw 'Bundle validation/install failed. Existing models were preserved.'}
}
if(-not (Test-Path (Join-Path $bundlePath 'manifest.json'))){throw "Missing $BundleDir/manifest.json. Install a verified bundle first."}
$env:AHR_MODEL_BUNDLE_DIR='./'+($BundleDir -replace '\\','/')
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
