param(
  [ValidateSet('all', 'baseline', 'web_injection', 'auth_abuse')]
  [string]$Profile = 'all',
  [ValidateRange(1, 20)]
  [int]$Repeat = 2
)

$ErrorActionPreference = 'Stop'
$stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$files = @(
  'docker-compose.yml',
  'sensors/suricata/compose.fragment.yml',
  'sensors/falco/compose.fragment.yml',
  'sensors/wazuh/compose.fragment.yml',
  'pipeline/compose.fragment.yml',
  'app/compose.fragment.yml'
)
$composeArgs = @('--env-file', '.env')
foreach ($file in $files) { $composeArgs += @('-f', $file) }

function Invoke-Collector([string[]]$arguments) {
  docker compose @composeArgs exec -T backend python -m dataset_collection.cli @arguments
  if ($LASTEXITCODE -ne 0) { throw "Dataset collection failed: $arguments" }
}

if ($Profile -in @('all', 'baseline')) {
  Invoke-Collector @('--target', 'http://nginx', 'run-benign', '--scenario-id', "dvwa_baseline_$stamp", '--repeat', $Repeat, '--notes', 'dvwa-training-baseline')
}

if ($Profile -in @('all', 'web_injection')) {
  foreach ($attack in 'sql_injection', 'xss', 'command_injection', 'file_inclusion') {
    Invoke-Collector @('--target', 'http://nginx', 'run-controlled', $attack, '--scenario-id', "dvwa_web_${attack}_$stamp", '--repeat', $Repeat, '--notes', 'dvwa-training-web-injection')
  }
}

if ($Profile -in @('all', 'auth_abuse')) {
  foreach ($attack in 'brute_force', 'scanner_pattern') {
    Invoke-Collector @('--target', 'http://nginx', 'run-controlled', $attack, '--scenario-id', "dvwa_auth_${attack}_$stamp", '--repeat', $Repeat, '--notes', 'dvwa-training-auth-abuse')
  }
}

Invoke-Collector @('export')
Write-Output "Dataset export completed: profile=$Profile repeat=$Repeat"
