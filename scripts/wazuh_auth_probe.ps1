[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class AhrWazuhNativeLogon
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string username,
        string domain,
        string password,
        int logonType,
        int logonProvider,
        out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

$marker = 'ahr_wazuh_' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + '_' + $PID
$token = [IntPtr]::Zero
$ok = [AhrWazuhNativeLogon]::LogonUser(
    $marker,
    '.',
    'AHR-IDPS-intentionally-invalid-password',
    2,
    0,
    [ref]$token)

if ($ok) {
    [void][AhrWazuhNativeLogon]::CloseHandle($token)
    throw 'Unexpectedly authenticated the deliberately nonexistent probe account.'
}

$nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ($nativeError -eq 0) {
    throw 'LogonUser failed without returning a Windows error code.'
}

# Emit only the unique username. Windows Security auditing, when enabled, now
# has a genuine failed interactive logon for the native Wazuh agent to collect.
$marker

