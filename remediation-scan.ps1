<#
.SYNOPSIS
    Remediation Scanner — Quét và gỡ bỏ dấu vết UAC Bypass + Shellcode Runner
.DESCRIPTION
    Script kiểm tra hệ thống để phát hiện và gỡ bỏ dấu vết của chuỗi tấn công
    UAC Bypass (test.exe) + Shellcode Runner (ConsoleApp1.exe).

    CẢNH BÁO: Chạy script này với quyền Administrator.
.EXAMPLE
    # Chế độ quét (chỉ báo cáo, không xóa gì)
    .\remediation-scan.ps1 -ScanOnly

    # Chế độ gỡ bỏ (quét + dọn dẹp)
    .\remediation-scan.ps1 -Remediate
#>

param(
    [switch]$ScanOnly,
    [switch]$Remediate
)

$ErrorActionPreference = "Continue"

# ============================================================
# Cấu hình IOC (Indicators of Compromise)
# ============================================================

# Tên tiến trình nghi ngờ
$SuspiciousProcessNames = @(
    "ConsoleApp1",
    "test"
)

# Đường dẫn file nghi ngờ
$SuspiciousPaths = @(
    "C:\update\ConsoleApp1.exe",
    "C:\update\",
    "$env:USERPROFILE\Desktop\test.exe",
    "$env:USERPROFILE\Downloads\test.exe"
)

# Registry keys dùng trong UAC bypass
$UACBypassRegKeys = @(
    "HKCU:\Software\Classes\ms-settings\shell\open\command",
    "HKCU:\Software\Classes\mscfile\shell\open\command"
)

# Port nghi ngờ (reverse shell)
$SuspiciousPorts = @(4444, 4443, 8080, 8443, 1337)

# Auto-elevated binaries thường bị lợi dụng
$AutoElevatedBinaries = @(
    "fodhelper.exe",
    "eventvwr.exe",
    "ComputerDefaults.exe",
    "sdclt.exe",
    "slui.exe"
)

# ============================================================
# Hàm tiện ích
# ============================================================

function Write-Finding {
    param(
        [string]$Level,   # OK, INFO, WARNING, CRITICAL
        [string]$Message
    )
    switch ($Level) {
        "OK"       { Write-Host "  [OK] $Message" -ForegroundColor Green }
        "INFO"     { Write-Host "  [i]  $Message" -ForegroundColor Cyan }
        "WARNING"  { Write-Host "  [!]  $Message" -ForegroundColor Yellow }
        "CRITICAL" { Write-Host "  [X]  $Message" -ForegroundColor Red }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor DarkGray
}

$global:TotalFindings = 0
$global:CriticalFindings = 0
$global:RemediationActions = @()

function Add-Finding {
    param(
        [string]$Level,
        [string]$Message,
        [string]$RemediationAction = ""
    )
    Write-Finding -Level $Level -Message $Message
    if ($Level -eq "CRITICAL" -or $Level -eq "WARNING") {
        $global:TotalFindings++
        if ($Level -eq "CRITICAL") { $global:CriticalFindings++ }
        if ($RemediationAction) {
            $global:RemediationActions += $RemediationAction
        }
    }
}

# ============================================================
# Bước 1: Kiểm tra tiến trình
# ============================================================

function Scan-Processes {
    Write-Section "BUOC 1: KIEM TRA TIEN TRINH"

    # Tìm tiến trình đáng ngờ theo tên
    foreach ($name in $SuspiciousProcessNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($proc in $procs) {
                Add-Finding "CRITICAL" `
                    "Tien trinh dang nghi dang chay: $($proc.Name) (PID: $($proc.Id), Path: $($proc.Path))" `
                    "Stop-Process -Id $($proc.Id) -Force"
            }
        }
    }

    # Tìm tiến trình chạy từ đường dẫn đáng ngờ
    $allProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
    foreach ($proc in $allProcs) {
        if ($proc.Path -like "*\update\*" -or
            $proc.Path -like "*\temp\*.exe" -and $proc.Path -notlike "*Windows\Temp*") {
            Add-Finding "WARNING" `
                "Tien trinh chay tu duong dan bat thuong: $($proc.Name) (PID: $($proc.Id), Path: $($proc.Path))" `
                "Stop-Process -Id $($proc.Id) -Force"
        }
    }

    # Kiểm tra chain: auto-elevated binary gần đây
    $recentAutoElevated = $allProcs | Where-Object {
        $AutoElevatedBinaries -contains (Split-Path $_.Path -Leaf -ErrorAction SilentlyContinue)
    }
    if ($recentAutoElevated) {
        foreach ($proc in $recentAutoElevated) {
            Add-Finding "WARNING" `
                "Auto-elevated binary dang chay: $($proc.Name) — co the la phan cua UAC bypass chain"
        }
    }

    if ($global:TotalFindings -eq 0) {
        Add-Finding "OK" "Khong tim thay tien trinh dang nghi"
    }
}

# ============================================================
# Bước 2: Kiểm tra kết nối mạng
# ============================================================

function Scan-Network {
    Write-Section "BUOC 2: KIEM TRA KET NOI MANG"

    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    # Kiểm tra port nghi ngờ
    foreach ($port in $SuspiciousPorts) {
        $suspicious = $connections | Where-Object { $_.RemotePort -eq $port }
        if ($suspicious) {
            foreach ($conn in $suspicious) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                Add-Finding "CRITICAL" `
                    "Ket noi den port $port: PID=$($conn.OwningProcess) ($($proc.Name)), Remote=$($conn.RemoteAddress):$($conn.RemotePort)" `
                    "Stop-Process -Id $($conn.OwningProcess) -Force; New-NetFirewallRule -DisplayName 'Block $($conn.RemoteAddress)' -Direction Outbound -RemoteAddress $($conn.RemoteAddress) -Action Block"
            }
        }
    }

    # Kiểm tra kết nối từ tiến trình ở đường dẫn lạ
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc.Path -and
            $proc.Path -notlike "C:\Windows\*" -and
            $proc.Path -notlike "C:\Program Files*" -and
            $proc.Path -notlike "C:\Program Files (x86)\*") {
            Add-Finding "INFO" `
                "Ket noi tu tien trinh ngoai he thong: $($proc.Name) ($($proc.Path)) -> $($conn.RemoteAddress):$($conn.RemotePort)"
        }
    }

    if ($global:TotalFindings -eq 0) {
        Add-Finding "OK" "Khong tim thay ket noi mang dang nghi"
    }
}

# ============================================================
# Bước 3: Kiểm tra Registry
# ============================================================

function Scan-Registry {
    Write-Section "BUOC 3: KIEM TRA REGISTRY"

    # UAC bypass keys
    foreach ($key in $UACBypassRegKeys) {
        if (Test-Path $key) {
            $value = Get-ItemProperty $key -ErrorAction SilentlyContinue
            Add-Finding "CRITICAL" `
                "Tim thay UAC bypass registry key: $key (Value: $($value.'(default)'))" `
                "Remove-Item '$key' -Recurse -Force"
        }
    }

    # Run keys (persistence)
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object {
            $_.Name -notlike "PS*" -and (
                $_.Value -like "*ConsoleApp*" -or
                $_.Value -like "*update\*" -or
                $_.Value -like "*test.exe*"
            )
        } | ForEach-Object {
            Add-Finding "CRITICAL" `
                "Persistence entry dang nghi: $key\$($_.Name) = $($_.Value)" `
                "Remove-ItemProperty -Path '$key' -Name '$($_.Name)' -Force"
        }
    }

    if ($global:TotalFindings -eq 0) {
        Add-Finding "OK" "Khong tim thay registry key dang nghi"
    }
}

# ============================================================
# Bước 4: Kiểm tra file hệ thống
# ============================================================

function Scan-Files {
    Write-Section "BUOC 4: KIEM TRA FILE HE THONG"

    foreach ($path in $SuspiciousPaths) {
        $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($path)
        if (Test-Path $expandedPath) {
            $item = Get-Item $expandedPath -ErrorAction SilentlyContinue
            if ($item.PSIsContainer) {
                $files = Get-ChildItem $expandedPath -ErrorAction SilentlyContinue
                if ($files) {
                    Add-Finding "WARNING" `
                        "Thu muc staging ton tai va co $($files.Count) file: $expandedPath" `
                        "Remove-Item '$expandedPath' -Recurse -Force"
                }
            } else {
                $hash = (Get-FileHash $expandedPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                Add-Finding "CRITICAL" `
                    "File ma doc ton tai: $expandedPath (SHA256: $hash)" `
                    "Remove-Item '$expandedPath' -Force"
            }
        }
    }

    if ($global:TotalFindings -eq 0) {
        Add-Finding "OK" "Khong tim thay file dang nghi"
    }
}

# ============================================================
# Bước 5: Kiểm tra Scheduled Tasks
# ============================================================

function Scan-ScheduledTasks {
    Write-Section "BUOC 5: KIEM TRA SCHEDULED TASKS"

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $actions = $_.Actions | Where-Object { $_.Execute }
        $actions | Where-Object {
            $_.Execute -like "*ConsoleApp*" -or
            $_.Execute -like "*update\*" -or
            $_.Execute -like "*test.exe*"
        }
    }

    if ($tasks) {
        foreach ($task in $tasks) {
            Add-Finding "CRITICAL" `
                "Scheduled task dang nghi: $($task.TaskName) (Execute: $($task.Actions[0].Execute))" `
                "Unregister-ScheduledTask -TaskName '$($task.TaskName)' -Confirm:`$false"
        }
    } else {
        Add-Finding "OK" "Khong tim thay scheduled task dang nghi"
    }
}

# ============================================================
# Tổng hợp và thực hiện gỡ bỏ
# ============================================================

function Show-Summary {
    Write-Section "TONG HOP"

    Write-Host ""
    Write-Host "  Tong so phat hien: $($global:TotalFindings)" -ForegroundColor $(if ($global:TotalFindings -gt 0) { "Red" } else { "Green" })
    Write-Host "  Muc Critical:      $($global:CriticalFindings)" -ForegroundColor $(if ($global:CriticalFindings -gt 0) { "Red" } else { "Green" })

    if ($global:RemediationActions.Count -gt 0) {
        Write-Host ""
        Write-Host "  Hanh dong go bo can thuc hien:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $global:RemediationActions.Count; $i++) {
            Write-Host "    $($i+1). $($global:RemediationActions[$i])" -ForegroundColor Cyan
        }
    }
}

function Invoke-Remediation {
    if ($global:RemediationActions.Count -eq 0) {
        Write-Host ""
        Write-Host "  Khong co hanh dong go bo nao can thuc hien." -ForegroundColor Green
        return
    }

    Write-Section "THUC HIEN GO BO"

    Write-Host ""
    Write-Host "  CANH BAO: Cac hanh dong sau se duoc thuc hien:" -ForegroundColor Red
    for ($i = 0; $i -lt $global:RemediationActions.Count; $i++) {
        Write-Host "    $($i+1). $($global:RemediationActions[$i])" -ForegroundColor Yellow
    }

    Write-Host ""
    $confirm = Read-Host "  Ban co chac chan muon tiep tuc? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "  Da huy." -ForegroundColor Yellow
        return
    }

    foreach ($action in $global:RemediationActions) {
        Write-Host "  Thuc hien: $action" -ForegroundColor Cyan
        try {
            Invoke-Expression $action
            Write-Host "    -> Thanh cong" -ForegroundColor Green
        }
        catch {
            Write-Host "    -> Loi: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Go bo hoan tat. Khuyen nghi:" -ForegroundColor Green
    Write-Host "    1. Chay Windows Defender Full Scan: Start-MpScan -ScanType FullScan" -ForegroundColor White
    Write-Host "    2. Doi mat khau cac tai khoan" -ForegroundColor White
    Write-Host "    3. Giam sat he thong them 24-48 gio" -ForegroundColor White
    Write-Host "    4. Kiem tra lai bang cach chay script nay lan nua" -ForegroundColor White
}

# ============================================================
# Main
# ============================================================

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "  Remediation Scanner — Blue Team Tool" -ForegroundColor Cyan
Write-Host "  Quet va go bo dau vet UAC Bypass" -ForegroundColor Cyan
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $ScanOnly -and -not $Remediate) {
    Write-Host "  Su dung:" -ForegroundColor Yellow
    Write-Host "    .\remediation-scan.ps1 -ScanOnly      # Chi quet, khong xoa gi" -ForegroundColor White
    Write-Host "    .\remediation-scan.ps1 -Remediate      # Quet va go bo" -ForegroundColor White
    Write-Host ""
    $ScanOnly = $true
}

# Chạy các bước quét
Scan-Processes
Scan-Network
Scan-Registry
Scan-Files
Scan-ScheduledTasks
Show-Summary

if ($Remediate) {
    Invoke-Remediation
} else {
    Write-Host ""
    Write-Host "  CHE DO SCAN ONLY: Khong thay doi gi tren he thong." -ForegroundColor Yellow
    Write-Host "  De go bo, chay lai voi: .\remediation-scan.ps1 -Remediate" -ForegroundColor Yellow
}

Write-Host ""
