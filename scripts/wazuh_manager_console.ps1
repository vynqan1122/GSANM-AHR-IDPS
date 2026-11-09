param([switch]$SetupAccess)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$credentialFile = Join-Path $root 'secrets/wazuh-api.json'

$open = Test-NetConnection -ComputerName 127.0.0.1 -Port 55000 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $open) { throw 'Wazuh Manager API is not listening on 127.0.0.1:55000' }

if ($SetupAccess -and -not (Test-Path -LiteralPath $credentialFile)) {
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $credentials = @{ username = 'ahr-dashboard-reader'; password = ([Convert]::ToBase64String($bytes) + 'aA1!') }
    $setup = @'
import sys,json
from wazuh.security import get_users,get_roles,create_user,set_user_role
data=json.load(sys.stdin)
users={u['username']:u['id'] for u in get_users().affected_items}
if data['username'] in users:
    raise RuntimeError('User already exists but local credential file is missing; existing credentials were not changed.')
roles={r['name']:r['id'] for r in get_roles().affected_items}
result=create_user(username=data['username'],password=data['password'])
if result.failed_items: raise RuntimeError('Cannot create read-only API user')
uid=next(u['id'] for u in get_users().affected_items if u['username']==data['username'])
result=set_user_role(user_id=[str(uid)],role_ids=[str(roles['readonly'])])
if result.failed_items: raise RuntimeError('Cannot assign read-only API role')
print('Read-only API access created; existing accounts unchanged.')
'@
    $credentials | ConvertTo-Json -Compress | docker exec -i ahr-idps-wazuh-manager-1 /var/ossec/framework/python/bin/python3 -c $setup
    if ($LASTEXITCODE -ne 0) { throw 'Wazuh API account setup failed; no credential file was written.' }
    New-Item -ItemType Directory -Path (Split-Path $credentialFile) -Force | Out-Null
    [IO.File]::WriteAllText($credentialFile, ($credentials | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @([Security.Principal.WindowsIdentity]::GetCurrent().Name, 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow'))
    }
    Set-Acl -LiteralPath $credentialFile -AclObject $acl
}

if (-not (Test-Path -LiteralPath $credentialFile)) {
    throw 'Run scripts/wazuh_manager_console.ps1 -SetupAccess once to create a dedicated read-only API account.'
}
$credentials = Get-Content -Raw -LiteralPath $credentialFile | ConvertFrom-Json
$basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($credentials.username + ':' + $credentials.password))
# Pass authorization on stdin, never in process arguments or console output.
$token = ('header = "Authorization: Basic ' + $basic + '"') | curl.exe --config - --silent --show-error --fail -k -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true'
if ($LASTEXITCODE -ne 0 -or -not $token) { throw 'Wazuh API authentication failed.' }
$token = ($token -join '').Trim()
$manager = ('header = "Authorization: Bearer ' + $token + '"') | curl.exe --config - --silent --show-error --fail -k 'https://127.0.0.1:55000/manager/status'
if ($LASTEXITCODE -ne 0) { throw 'Wazuh API manager status request failed.' }
$manager = $manager | ConvertFrom-Json

$status = docker exec ahr-idps-wazuh-manager-1 /var/ossec/bin/wazuh-control status 2>&1
[PSCustomObject]@{
    Api = 'https://127.0.0.1:55000'
    ApiPortOpen = $open
    Authentication = 'PASS'
    ApiRole = 'readonly'
    ManagerApiError = $manager.error
    ManagerDaemons = $manager.data.affected_items
    Status = ($status -join "`n")
} | ConvertTo-Json -Depth 4
