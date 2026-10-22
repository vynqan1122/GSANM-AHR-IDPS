param(
  [Parameter(Mandatory = $true)]
  [string]$InputPath,
  [int]$MaxRows = 30000,
  [switch]$InstallXgboost,
  [string]$OutputDir = 'experiments/comparison/network'
)

$ErrorActionPreference = 'Stop'

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
  throw 'Python 3 is required. Use the AI Docker service or add Python to PATH.'
}

$args = @(
  'scripts/train_kaggle_network.py',
  '--input', $InputPath,
  '--output-dir', $OutputDir,
  '--max-rows', $MaxRows
)
if ($InstallXgboost) { $args += '--install-xgboost' }
& $python.Source @args
if ($LASTEXITCODE -ne 0) { throw "Network training failed with exit code $LASTEXITCODE" }
