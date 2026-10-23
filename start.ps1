# Chay start.sh bang Git Bash tu PowerShell. Lenh `bash` trong PowerShell la
# WSL (C:\Windows\System32\bash.exe), khong thay Docker Desktop neu distro chua
# bat WSL integration, nen phai goi Git Bash truc tiep.
#   .\start.ps1               bat toan bo
#   .\start.ps1 stop          tat toan bo
#   .\start.ps1 status
$ErrorActionPreference = 'Stop'

$candidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    "$env:LocalAppData\Programs\Git\bin\bash.exe"
)
$gitBash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $gitBash) {
    throw 'Khong tim thay Git Bash. Cai Git for Windows roi chay lai.'
}

& $gitBash (Join-Path $PSScriptRoot 'start.sh') @args
exit $LASTEXITCODE
