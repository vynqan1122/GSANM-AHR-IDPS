[CmdletBinding()]
param([ValidateSet('start','status','health','stop','logs','rollback')][string]$Command='status',[switch]$NoBuild)
$ErrorActionPreference='Stop'
$projectPath = Split-Path -Parent $PSScriptRoot
$wslOutput = & wsl.exe -d Ubuntu-24.04 -- wslpath -u ($projectPath.Replace('\','/'))
if ($LASTEXITCODE -ne 0) { throw 'WSL Ubuntu-24.04 and Docker Linux Engine are required.' }
$wslProjectPath = ($wslOutput | Out-String).Trim()
if (-not $wslProjectPath) { throw 'Cannot resolve the project path in WSL.' }
$bashArguments=@("$wslProjectPath/scripts/genti_control.sh",$Command)
if($NoBuild){$bashArguments+='--no-build'}
& wsl.exe -d Ubuntu-24.04 -u root -- bash @bashArguments
exit $LASTEXITCODE
