$ErrorActionPreference = 'Stop'

$base = 'http://127.0.0.1:8080'
$paths = @(
    '/healthz', '/', '/dashboard/', '/api/health', '/api/system/health',
    '/api/events?page_size=1', '/api/alerts?page_size=1',
    '/api/incidents?page_size=1', '/api/network/summary', '/api/containers',
    '/api/models', '/api/rules?source=generated&page_size=1',
    '/api/responses?page_size=1', '/api/dashboard/overview',
    '/api/dashboard/timeseries', '/api/experiments'
)

function Assert-Http([string]$Path) {
    $response = Invoke-WebRequest -Uri ($base + $Path) -UseBasicParsing -TimeoutSec 15
    if ($response.StatusCode -ne 200) {
        throw "$Path returned HTTP $($response.StatusCode)"
    }
    [PSCustomObject]@{ Path = $Path; Status = $response.StatusCode; Bytes = $response.RawContentLength }
}

$portRows = foreach ($port in 8080, 1514, 1515) {
    $open = Test-NetConnection -ComputerName 127.0.0.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $open) { throw "127.0.0.1:$port is closed" }
    [PSCustomObject]@{ Host = '127.0.0.1'; Port = $port; Open = $open }
}

$apiRows = $paths | ForEach-Object { Assert-Http $_ }

$websocketRows = & python .\scripts\websocket_acceptance.py
if ($LASTEXITCODE -ne 0) { throw 'WebSocket acceptance failed' }

$dashboard = Invoke-WebRequest -Uri "$base/dashboard/" -UseBasicParsing -TimeoutSec 15
$bundlePath = [regex]::Match($dashboard.Content, 'src="([^"]+\.js)"').Groups[1].Value
if (-not $bundlePath) { throw 'Dashboard HTML did not reference a JavaScript bundle' }
$bundle = Invoke-WebRequest -Uri ($base + $bundlePath) -UseBasicParsing -TimeoutSec 15
foreach ($label in 'Live events','Alerts','Incidents','AI Monitor','Generated rules','Responses','System Health','Wazuh Manager','Sensor health') {
    if (-not $bundle.Content.Contains($label)) { throw "Dashboard bundle is missing '$label'" }
}

[PSCustomObject]@{
    Result = 'PASS'
    Ports = $portRows
    Interfaces = $apiRows
    WebSockets = ($websocketRows | ConvertFrom-Json)
    DashboardBundle = $bundlePath
} | ConvertTo-Json -Depth 6
