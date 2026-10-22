<#
.SYNOPSIS
    AHR-IDPS Windows PowerShell Unified Lifecycle Management Controller
.DESCRIPTION
    Script điều khiển toàn bộ 18 dịch vụ của AHR-IDPS thông qua WSL 2 / Docker
    Hỗ trợ bật / tắt / restart / kiểm tra trạng thái / kiểm tra sức khỏe hệ thống.
.EXAMPLE
    .\ahr_control.ps1 start
    .\ahr_control.ps1 stop
    .\ahr_control.ps1 restart
    .\ahr_control.ps1 status
    .\ahr_control.ps1 health
    .\ahr_control.ps1 logs backend
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet('start', 'up', 'stop', 'down', 'restart', 'status', 'ps', 'health', 'logs', 'help', '')]
    [string]$Command = 'status',

    [Parameter(Position = 1)]
    [string]$Service = ''
)

$ErrorActionPreference = 'Stop'

# Lấy thư mục gốc dự án
$ProjectDir = $PSScriptRoot
# Chuyển đổi đường dẫn Windows sang đường dẫn WSL (ví dụ: D:\GSANM\ahr-idps -> /mnt/d/GSANM/ahr-idps)
$DriveLetter = $ProjectDir.Substring(0, 1).ToLower()
$SubPath = $ProjectDir.Substring(2).Replace('\', '/')
$WslPath = "/mnt/$DriveLetter$SubPath"

function Show-Help {
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "             AHR-IDPS POWERSHELL MANAGEMENT TOOL                     " -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "Cú pháp:" -ForegroundColor Yellow
    Write-Host "  .\ahr_control.ps1 start          - Bật toàn bộ 18 dịch vụ theo thứ tự đúng" -ForegroundColor White
    Write-Host "  .\ahr_control.ps1 stop           - Tắt toàn bộ 18 dịch vụ bảo toàn dữ liệu" -ForegroundColor White
    Write-Host "  .\ahr_control.ps1 restart        - Khởi động lại toàn bộ hệ thống" -ForegroundColor White
    Write-Host "  .\ahr_control.ps1 status         - Kiểm tra trạng thái 18 container" -ForegroundColor White
    Write-Host "  .\ahr_control.ps1 health         - Kiểm tra sâu kết nối DB, API, Sensors, AI" -ForegroundColor White
    Write-Host "  .\ahr_control.ps1 logs [service] - Xem log (ví dụ: .\ahr_control.ps1 logs backend)" -ForegroundColor White
    Write-Host ""
}

if ($Command -eq '' -or $Command -eq 'help') {
    Show-Help
    exit 0
}

# Kiểm tra WSL đang hoạt động
try {
    $wslCheck = wsl.exe -d Ubuntu-24.04 -u root -- echo "WSL_OK" 2>$null
    if ($wslCheck -notmatch "WSL_OK") {
        Write-Warning "Không kết nối được tới Ubuntu-24.04, thử wsl mặc định..."
        $wslDistroArg = @()
    } else {
        $wslDistroArg = @('-d', 'Ubuntu-24.04')
    }
} catch {
    $wslDistroArg = @()
}

$WslCmd = "cd '$WslPath' && ./scripts/ahr_control.sh $Command $Service"

# Thực thi lệnh thông qua WSL với user root để đảm bảo quyền truy cập Docker daemon
& wsl.exe @wslDistroArg -u root -- bash -c "$WslCmd"
