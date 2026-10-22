param(
  [Parameter(Mandatory=$true)][string]$Endpoint,
  [Parameter(Mandatory=$true)][string]$TokenFile
)
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:COLAB_ENDPOINT=$Endpoint
$env:COLAB_TOKEN_FILE=(Resolve-Path -LiteralPath $TokenFile).Path
if (-not $Endpoint.StartsWith('https://')) {throw 'Endpoint must be HTTPS Colab tunnel origin'}
$ca=@('--env-file','.env')
foreach($f in 'docker-compose.yml','sensors/suricata/compose.fragment.yml','sensors/falco/compose.fragment.yml','sensors/wazuh/compose.fragment.yml','pipeline/compose.fragment.yml','app/compose.fragment.yml','ai/compose.fragment.yml','ai/compose.colab.yml'){$ca+=@('-f',$f)}
docker compose @ca --profile colab config --quiet
if($LASTEXITCODE -ne 0){throw 'Compose validation failed'}
docker compose @ca build colab-bridge
if($LASTEXITCODE -ne 0){throw 'Bridge image build failed'}
$project=(docker compose @ca --profile colab config --format json | ConvertFrom-Json).name
$bundle=docker ps -q --filter "label=com.docker.compose.project=$project" --filter 'label=com.docker.compose.service=ai-bundle'
if($bundle){docker stop $bundle; if($LASTEXITCODE -ne 0){throw 'Could not stop overlapping local bundle'}}
# Stop overlapping local scorers; keep pipeline/incidents/evidence local.
docker compose @ca stop ai-network ai-log graph-builder fusion-engine
if($LASTEXITCODE -ne 0){throw 'Could not stop local AI'}
docker compose @ca --profile colab up -d --no-deps --wait --wait-timeout 120 colab-bridge incident-engine
if($LASTEXITCODE -ne 0){throw 'Colab bridge unhealthy. Inspect logs; pending events are preserved.'}
