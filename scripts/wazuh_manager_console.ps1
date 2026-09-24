$ErrorActionPreference = 'Stop'

$open = Test-NetConnection -ComputerName 127.0.0.1 -Port 55000 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $open) { throw 'Wazuh Manager API is not listening on 127.0.0.1:55000' }

$status = docker exec ahr-idps-wazuh-manager-1 /var/ossec/bin/wazuh-control status 2>&1
[PSCustomObject]@{
    Api = 'https://127.0.0.1:55000'
    ApiPortOpen = $open
    Status = ($status -join "`n")
} | ConvertTo-Json -Depth 4
