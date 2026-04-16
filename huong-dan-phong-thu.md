# Hướng dẫn Phòng thủ UAC Bypass — Dành cho Blue Team

> Tài liệu này giải thích cách phòng chống kỹ thuật UAC Bypass bằng ngôn ngữ đơn giản,
> phù hợp cho người mới bắt đầu tìm hiểu về an ninh mạng.

---

## Mục lục

1. [UAC Bypass là gì?](#1-uac-bypass-là-gì)
2. [Tóm tắt chuỗi tấn công trong dự án này](#2-tóm-tắt-chuỗi-tấn-công-trong-dự-án-này)
3. [Kịch bản A — Khi có source code: Tính payload và phát hiện](#3-kịch-bản-a--khi-có-source-code)
4. [Kịch bản B — Khi chỉ có file .exe (không có source)](#4-kịch-bản-b--khi-chỉ-có-file-exe)
5. [Kịch bản C — Mã độc đã chạy: Phát hiện và gỡ bỏ](#5-kịch-bản-c--mã-độc-đã-chạy-phát-hiện-và-gỡ-bỏ)
6. [Kịch bản D — Phòng ngừa: Chặn trước khi bị tấn công](#6-kịch-bản-d--phòng-ngừa)
7. [Kịch bản E — Giám sát liên tục với Sysmon](#7-kịch-bản-e--giám-sát-liên-tục-với-sysmon)
8. [Kịch bản F — Phân tích hành vi trong Sandbox](#8-kịch-bản-f--phân-tích-hành-vi-trong-sandbox)
9. [Tổng hợp công cụ BlueTeamDetector](#9-tổng-hợp-công-cụ-bluetemdetector)
10. [Bảng tham chiếu nhanh](#10-bảng-tham-chiếu-nhanh)

---

## 1. UAC Bypass là gì?

### Giải thích đơn giản

Khi bạn cài phần mềm trên Windows, thường sẽ thấy một hộp thoại hỏi:
**"Do you want to allow this app to make changes to your device?"** — đó là **UAC (User Account Control)**.

UAC giống như **người bảo vệ** ở cổng tòa nhà. Mỗi khi ai muốn vào khu vực quan trọng,
bảo vệ sẽ hỏi: "Anh/chị có được phép không?"

**UAC Bypass** là khi kẻ xấu tìm cách **lẻn qua bảo vệ mà không bị hỏi**.
Kết quả: phần mềm độc hại chạy với **quyền Administrator** (quyền cao nhất) mà người dùng không hề biết.

### Tại sao nguy hiểm?

| Không có UAC Bypass | Có UAC Bypass |
|---------------------|---------------|
| Mã độc chạy quyền thường, bị giới hạn | Mã độc chạy quyền Admin, làm được mọi thứ |
| Không thể sửa file hệ thống | Có thể sửa/xóa file Windows |
| Không thể cài backdoor sâu | Cài backdoor tồn tại sau khởi động lại |
| Người dùng thấy cảnh báo UAC | Người dùng KHÔNG thấy gì cả |

### Kỹ thuật MITRE ATT&CK

- **ID:** T1548.002
- **Tên:** Abuse Elevation Control Mechanism: Bypass User Account Control
- **Ý nghĩa:** Kẻ tấn công lợi dụng cơ chế nâng quyền của Windows để chạy code với quyền cao mà không cần sự đồng ý của người dùng.

---

## 2. Tóm tắt chuỗi tấn công trong dự án này

Dự án sử dụng **2 phần mềm độc hại phối hợp**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     CHUỖI TẤN CÔNG                              │
│                                                                  │
│  Bước 1: test.exe (quyền thường)                                │
│     │                                                            │
│     ├── Gọi winver.exe qua AppInfo RPC (lấy debug object)       │
│     │                                                            │
│     ├── Gọi ComputerDefaults.exe (binary "auto-elevated")       │
│     │                                                            │
│     └── Tạo ConsoleApp1.exe với QUYỀN ADMIN                     │
│            │                                                     │
│  Bước 2: ConsoleApp1.exe (quyền Admin - KHÔNG có cảnh báo UAC)  │
│     │                                                            │
│     ├── Giải mã shellcode bằng XOR                               │
│     │                                                            │
│     ├── Cấp phát bộ nhớ có quyền thực thi (VirtualAlloc RWX)    │
│     │                                                            │
│     ├── Chép shellcode vào bộ nhớ (Marshal.Copy)                 │
│     │                                                            │
│     └── Tạo thread chạy shellcode → REVERSE SHELL về attacker    │
│                                                                  │
│  Kết quả: Attacker có shell quyền Admin trên máy nạn nhân       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Kịch bản A — Khi có source code

> **Câu hỏi:** Nếu biết trước mã nguồn C#, có thể tính ra payload để detect không?
>
> **Trả lời:** CÓ. Đây là cách dễ nhất.

### 3.1 Trích xuất IOC từ source code

Từ file `ConsoleApp1/Program.cs`, ta biết:

| Thông tin | Giá trị | Cách dùng |
|-----------|---------|-----------|
| XOR Key | `0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22` | Dùng để giải mã shellcode và tạo YARA rule |
| Encrypted shellcode | Byte array 452 bytes | Hash nó để làm IOC |
| API imports | `VirtualAlloc`, `CreateThread`, `WaitForSingleObject` | Dấu hiệu shellcode runner |
| Đường dẫn staging | `C:\update\ConsoleApp1.exe` | Giám sát thư mục này |

### 3.2 Tạo YARA Rule từ source

YARA là công cụ quét file dựa trên mẫu (pattern). Giống như "dấu vân tay" của mã độc:

```yara
rule UACBypass_ConsoleApp1_FromSource {
    meta:
        description = "Phát hiện ConsoleApp1 shellcode runner dựa trên source code đã biết"
        author = "BlueTeam"
        mitre = "T1548.002"

    strings:
        // XOR key đặc trưng
        $xor_key = { AA BB CC DD EE FF 11 22 }

        // 16 bytes đầu của encrypted shellcode
        $enc_head = { 56 F3 4F 39 1E 17 D1 22 AA BB 8D 8C AF AF 43 73 }

        // Chuỗi trong chương trình
        $s1 = "ShellcodeRunner" ascii wide
        $s2 = "Shellcode decrypted" ascii wide
        $s3 = "nc -lvnp 4444" ascii wide

    condition:
        $xor_key or $enc_head or (2 of ($s*))
}
```

### 3.3 Chạy BlueTeamDetector (công cụ trong dự án)

```bash
cd BlueTeamDetector
dotnet run -- scan-repo ..
```

Công cụ sẽ quét source code và báo cáo tất cả dấu hiệu đáng ngờ.

---

## 4. Kịch bản B — Khi chỉ có file .exe

> **Câu hỏi:** Nếu nhận file .exe mà KHÔNG có source code, làm sao phát hiện?
>
> **Trả lời:** Dùng nhiều kỹ thuật phân tích khác nhau. Dưới đây là từng bước.

### 4.1 Tổng quan các kỹ thuật phân tích file binary

```
┌──────────────────────────────────────────────────┐
│         PHÂN TÍCH FILE .EXE KHÔNG CÓ SOURCE      │
│                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  │
│  │  Phân tích   │  │  Phân tích   │  │ Phân tích│  │
│  │    tĩnh     │  │   động      │  │  bộ nhớ  │  │
│  │  (Static)   │  │  (Dynamic)  │  │ (Memory) │  │
│  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  │
│         │                │               │        │
│  - Hash file      - Chạy sandbox   - Dump RAM     │
│  - Import table   - Theo dõi API   - Tìm shellcode│
│  - Entropy        - Giám sát mạng  - Strings      │
│  - YARA scan      - Process tree   - Decrypt       │
│  - Strings        - Registry       payload        │
│  - PE headers     - File changes                  │
│                                                   │
└──────────────────────────────────────────────────┘
```

### 4.2 Kỹ thuật 1: Kiểm tra Hash

**Hash** là "dấu vân tay số" của file. Mỗi file có một hash duy nhất.

```powershell
# Tính hash SHA256 của file
Get-FileHash -Algorithm SHA256 "C:\suspect\ConsoleApp1.exe"

# Kết quả ví dụ:
# Algorithm  Hash
# ---------  ----
# SHA256     A1B2C3D4E5F6...
```

Sau đó tra hash này trên:
- [VirusTotal](https://www.virustotal.com) — Cơ sở dữ liệu mã độc lớn nhất
- [Hybrid Analysis](https://hybrid-analysis.com) — Phân tích sandbox miễn phí

### 4.3 Kỹ thuật 2: Phân tích Import Table (bảng API)

Mỗi file .exe khi gọi hàm Windows sẽ **khai báo** trong bảng Import.
Đọc bảng này giống như xem **danh sách vũ khí** mà kẻ xấu mang theo:

| API Import nguy hiểm | Ý nghĩa | Mức cảnh báo |
|----------------------|----------|--------------|
| `VirtualAlloc` + `VirtualProtect` | Cấp phát bộ nhớ có thể thực thi | 🔴 Cao |
| `CreateThread` / `CreateRemoteThread` | Tạo thread (có thể chạy shellcode) | 🔴 Cao |
| `WriteProcessMemory` | Ghi vào bộ nhớ tiến trình khác | 🔴 Rất cao |
| `NtDuplicateObject` | Sao chép handle (dùng trong UAC bypass) | 🔴 Rất cao |
| `RpcStringBindingCompose` | Giao tiếp RPC (có thể gọi AppInfo) | 🟡 Trung bình |
| `CreateProcessW` với `EXTENDED_STARTUPINFO` | Tạo tiến trình với parent spoofing | 🔴 Cao |
| `WinHttpOpen` / `InternetOpen` | Kết nối mạng (callback/C2) | 🟡 Trung bình |

**Công cụ kiểm tra:**
- **pestudio** (miễn phí): Mở file .exe → xem tab "imports"
- **CFF Explorer**: Phần "Import Directory"
- **Python + pefile**: Xem mục 4.7 bên dưới

### 4.4 Kỹ thuật 3: Đo Entropy (độ hỗn loạn)

**Entropy** đo mức độ "ngẫu nhiên" của dữ liệu trong file.

| Entropy | Ý nghĩa |
|---------|---------|
| 0 - 3 | Dữ liệu có cấu trúc (text, code bình thường) |
| 3 - 6 | Bình thường cho hầu hết executable |
| 6 - 7 | Có khả năng chứa dữ liệu nén hoặc mã hóa |
| 7 - 8 | **Rất nghi ngờ** — dữ liệu bị mã hóa hoặc packed |

**Tại sao quan trọng?**

Trong `ConsoleApp1.exe`, shellcode đã bị XOR mã hóa. Khi compiler nhúng byte array này vào file .exe,
phần đó sẽ có entropy CAO (>7). Đây là dấu hiệu mạnh cho thấy file chứa payload bị làm mờ.

### 4.5 Kỹ thuật 4: Quét chuỗi (Strings)

**Strings** là các đoạn text đọc được bên trong file binary:

```powershell
# Dùng strings.exe từ Sysinternals
strings.exe -n 8 "C:\suspect\ConsoleApp1.exe"
```

Chuỗi đáng ngờ trong ConsoleApp1.exe:

| Chuỗi tìm thấy | Ý nghĩa |
|-----------------|---------|
| `VirtualAlloc` | Cấp phát bộ nhớ thực thi |
| `CreateThread` | Tạo thread mới |
| `ShellcodeRunner` | Tên namespace tiết lộ mục đích |
| `nc -lvnp 4444` | Lệnh listener reverse shell |
| `Shellcode decrypted` | Log message tiết lộ hành vi |
| `kernel32.dll` | Import từ kernel — bình thường nhưng kết hợp các chuỗi trên → nghi ngờ |

### 4.6 Kỹ thuật 5: YARA Rule cho binary

YARA rule hoạt động trên **file binary**, không cần source code:

```yara
rule Shellcode_Runner_Generic {
    meta:
        description = "Phát hiện shellcode runner pattern trong binary"
        mitre = "T1055, T1059"

    strings:
        // API calls phổ biến trong shellcode runner
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "CreateThread" ascii wide
        $api3 = "VirtualProtect" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "WaitForSingleObject" ascii wide

        // Dấu hiệu shellcode
        $sc1 = { FC 48 83 E4 F0 }  // Shellcode header phổ biến (x64)
        $sc2 = { FC E8 ?? 00 00 00 }  // Một dạng shellcode header khác

        // Pattern XOR decode loop (phổ biến)
        $xor_loop = { 30 ?? 4? FF C? 3B }  // XOR [reg], reg; INC; CMP

    condition:
        uint16(0) == 0x5A4D and   // File phải là PE (MZ header)
        (
            (3 of ($api*)) or       // Có 3+ API nghi ngờ
            any of ($sc*) or        // Có shellcode header
            $xor_loop               // Có XOR decode loop
        )
}

rule UAC_Bypass_Binary {
    meta:
        description = "Phát hiện UAC bypass indicators trong binary"
        mitre = "T1548.002"

    strings:
        $rpc1 = "201ef99a-7fa0-444c-9399-19ba84f12a1a" ascii wide  // AppInfo RPC GUID
        $bin1 = "ComputerDefaults" ascii wide
        $bin2 = "fodhelper" ascii wide
        $bin3 = "eventvwr" ascii wide
        $api1 = "NtDuplicateObject" ascii
        $api2 = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii
        $reg1 = "ms-settings\\shell\\open\\command" ascii wide
        $reg2 = "mscfile\\shell\\open\\command" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $rpc1 or
            ($api1 and $api2) or
            (any of ($bin*) and any of ($reg*))
        )
}
```

### 4.7 Script Python phân tích binary

Dự án cung cấp script `analyze_binary.py` (xem file trong repo) để phân tích nhanh file .exe:

```
python3 analyze_binary.py suspicious_file.exe
```

Script sẽ kiểm tra:
- ✅ Hash SHA256
- ✅ Import table (API nguy hiểm)
- ✅ Entropy từng section
- ✅ Strings đáng ngờ
- ✅ PE header anomalies
- ✅ Tổng hợp điểm rủi ro

### 4.8 Tóm tắt: So sánh có source vs không có source

| Tiêu chí | Có source code | Chỉ có file .exe |
|----------|---------------|-----------------|
| Độ chính xác | Rất cao (100%) | Cao (85-95%) |
| Thời gian phân tích | Nhanh (phút) | Trung bình (giờ) |
| Kỹ thuật chính | Đọc code, trích IOC | Import table, entropy, YARA, sandbox |
| Có thể giải mã payload? | Có (biết key) | Có thể (nếu tìm được key trong binary) |
| Phát hiện biến thể? | Khó (chỉ match exact) | Tốt hơn (match pattern hành vi) |

---

## 5. Kịch bản C — Mã độc đã chạy: Phát hiện và gỡ bỏ

> **Câu hỏi:** Nếu người dùng đã kích hoạt mã độc rồi, có cách nào phát hiện và gỡ không?
>
> **Trả lời:** CÓ. Dưới đây là quy trình từng bước.

### 5.1 Tổng quan quy trình ứng phó sự cố

```
┌────────────────────────────────────────────────────────────┐
│              QUY TRÌNH ỨNG PHÓ SỰ CỐ                      │
│                                                            │
│  Bước 1: PHÁT HIỆN                                        │
│  ├── Kiểm tra tiến trình đang chạy                        │
│  ├── Kiểm tra kết nối mạng bất thường                     │
│  └── Kiểm tra registry và scheduled tasks                 │
│                                                            │
│  Bước 2: NGĂN CHẶN (Containment)                          │
│  ├── Ngắt kết nối mạng ngay lập tức                       │
│  ├── Kill tiến trình mã độc                                │
│  └── Block IP của attacker trên firewall                   │
│                                                            │
│  Bước 3: GỠ BỎ (Eradication)                              │
│  ├── Xóa file mã độc                                      │
│  ├── Dọn registry keys bị sửa                             │
│  ├── Xóa scheduled tasks độc hại                          │
│  └── Kiểm tra persistence mechanisms                      │
│                                                            │
│  Bước 4: KHÔI PHỤC (Recovery)                              │
│  ├── Quét toàn bộ với antivirus                            │
│  ├── Đổi mật khẩu các tài khoản                           │
│  ├── Kiểm tra lại hệ thống                                │
│  └── Giám sát thêm 24-48 giờ                              │
│                                                            │
│  Bước 5: BÀI HỌC (Lessons Learned)                        │
│  └── Ghi lại sự cố và cải thiện phòng thủ                 │
└────────────────────────────────────────────────────────────┘
```

### 5.2 Bước 1: Phát hiện — Kiểm tra tiến trình

```powershell
# Liệt kê tất cả tiến trình, sắp xếp theo thời gian khởi tạo
Get-Process | Sort-Object StartTime -Descending | Select-Object -First 20 `
    Name, Id, StartTime, Path

# Tìm tiến trình chạy từ đường dẫn đáng ngờ
Get-Process | Where-Object {
    $_.Path -and (
        $_.Path -like "*\update\*" -or
        $_.Path -like "*\temp\*" -or
        $_.Path -like "*\Users\*\Desktop\*" -or
        $_.Path -like "*\Users\*\Downloads\*"
    )
} | Select-Object Name, Id, Path, StartTime

# Tìm tiến trình ConsoleApp1 cụ thể
Get-Process -Name "ConsoleApp1" -ErrorAction SilentlyContinue |
    Select-Object Name, Id, Path, StartTime
```

### 5.3 Bước 1: Phát hiện — Kiểm tra kết nối mạng

```powershell
# Xem tất cả kết nối TCP đang active
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $_ | Add-Member -NotePropertyName "ProcessName" -NotePropertyValue $proc.Name -PassThru |
             Add-Member -NotePropertyName "ProcessPath" -NotePropertyValue $proc.Path -PassThru
    } | Format-Table

# Tìm kết nối đến port 4444 (port mặc định của reverse shell trong PoC)
Get-NetTCPConnection | Where-Object {
    $_.RemotePort -eq 4444 -or
    $_.LocalPort -eq 4444
}

# Tìm kết nối từ tiến trình nằm ngoài thư mục Windows/Program Files
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc.Path -and
        $proc.Path -notlike "C:\Windows\*" -and
        $proc.Path -notlike "C:\Program Files*") {
        [PSCustomObject]@{
            Process = $proc.Name
            PID = $_.OwningProcess
            Path = $proc.Path
            RemoteIP = $_.RemoteAddress
            RemotePort = $_.RemotePort
        }
    }
} | Format-Table
```

### 5.4 Bước 1: Phát hiện — Kiểm tra Registry

UAC Bypass qua `fodhelper.exe` hoặc `eventvwr.exe` thường sửa registry:

```powershell
# Kiểm tra registry key dùng bởi fodhelper bypass
$fodhelperKey = "HKCU:\Software\Classes\ms-settings\shell\open\command"
if (Test-Path $fodhelperKey) {
    Write-Host "[CẢNH BÁO] Tìm thấy registry key UAC bypass (fodhelper)!" -ForegroundColor Red
    Get-ItemProperty $fodhelperKey
} else {
    Write-Host "[OK] Không tìm thấy fodhelper bypass key" -ForegroundColor Green
}

# Kiểm tra registry key dùng bởi eventvwr bypass
$eventvwrKey = "HKCU:\Software\Classes\mscfile\shell\open\command"
if (Test-Path $eventvwrKey) {
    Write-Host "[CẢNH BÁO] Tìm thấy registry key UAC bypass (eventvwr)!" -ForegroundColor Red
    Get-ItemProperty $eventvwrKey
} else {
    Write-Host "[OK] Không tìm thấy eventvwr bypass key" -ForegroundColor Green
}

# Kiểm tra Run keys (nơi mã độc thường đặt persistence)
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Write-Host "`n--- $key ---"
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS*
}
```

### 5.5 Bước 2: Ngăn chặn

```powershell
# 1. Ngắt mạng ngay lập tức (chặn reverse shell)
#    Cách nhanh nhất: tắt network adapter
Get-NetAdapter | Disable-NetAdapter -Confirm:$false

# 2. Kill tiến trình mã độc
# Kill theo tên
Stop-Process -Name "ConsoleApp1" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "test" -Force -ErrorAction SilentlyContinue

# Kill theo PID (thay 1234 bằng PID thực)
# Stop-Process -Id 1234 -Force

# 3. Block IP attacker trên firewall (thay IP thực)
New-NetFirewallRule -DisplayName "Block Attacker" `
    -Direction Outbound `
    -RemoteAddress "10.10.14.8" `
    -Action Block

# 4. Block port 4444
New-NetFirewallRule -DisplayName "Block Reverse Shell Port" `
    -Direction Outbound `
    -RemotePort 4444 `
    -Protocol TCP `
    -Action Block
```

### 5.6 Bước 3: Gỡ bỏ

```powershell
# 1. Xóa file mã độc
Remove-Item "C:\update\ConsoleApp1.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\update\" -Recurse -Force -ErrorAction SilentlyContinue

# 2. Dọn registry UAC bypass keys
Remove-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Recurse -Force -ErrorAction SilentlyContinue

# 3. Kiểm tra và xóa Scheduled Tasks đáng ngờ
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -and (
        $_.Actions.Execute -like "*update*" -or
        $_.Actions.Execute -like "*ConsoleApp*" -or
        $_.Actions.Execute -like "*temp*"
    )
} | ForEach-Object {
    Write-Host "[CẢNH BÁO] Scheduled task đáng ngờ: $($_.TaskName)" -ForegroundColor Red
    Write-Host "  Execute: $($_.Actions.Execute)"
    # Uncomment dòng dưới để xóa:
    # Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
}

# 4. Kiểm tra services đáng ngờ
Get-Service | Where-Object {
    $_.Status -eq 'Running' -and
    $_.BinaryPathName -and (
        $_.BinaryPathName -like "*update*" -or
        $_.BinaryPathName -like "*ConsoleApp*"
    )
}
```

### 5.7 Bước 4: Khôi phục

```powershell
# 1. Bật lại mạng
Get-NetAdapter | Enable-NetAdapter -Confirm:$false

# 2. Chạy Windows Defender full scan
Start-MpScan -ScanType FullScan

# 3. Cập nhật Windows Defender signatures
Update-MpSignature

# 4. Xóa firewall rules tạm (sau khi đã xác nhận an toàn)
# Remove-NetFirewallRule -DisplayName "Block Attacker"
# Remove-NetFirewallRule -DisplayName "Block Reverse Shell Port"
```

### 5.8 Script tự động: Remediation Scanner

Dự án cung cấp script PowerShell `remediation-scan.ps1` để tự động hóa toàn bộ quy trình trên.
Xem chi tiết ở **Mục 9**.

---

## 6. Kịch bản D — Phòng ngừa

> **Mục tiêu:** Cấu hình Windows để UAC Bypass KHÔNG thể hoạt động ngay từ đầu.

### 6.1 Nâng mức UAC lên cao nhất

```
Cách làm:
1. Mở "Change User Account Control settings" (gõ UAC trong Start Menu)
2. Kéo thanh trượt lên mức CAO NHẤT: "Always notify"
3. Nhấn OK
```

**Tại sao hiệu quả?**

Ở mức mặc định, Windows có danh sách các chương trình "auto-elevated" (ví dụ: `ComputerDefaults.exe`,
`fodhelper.exe`) — chúng được PHÉP chạy quyền Admin mà KHÔNG hỏi UAC. Kẻ tấn công lợi dụng điều này.

Khi đặt UAC ở mức cao nhất, **MỌI** chương trình đều phải hỏi, kể cả auto-elevated.

### 6.2 Dùng tài khoản Standard User (không phải Admin)

```
Cách làm:
1. Settings → Accounts → Family & other users
2. Tạo tài khoản mới với quyền "Standard User"
3. Dùng tài khoản này cho công việc hàng ngày
4. Chỉ dùng tài khoản Admin khi cần cài phần mềm
```

**Tại sao hiệu quả?**

UAC Bypass chỉ hoạt động khi người dùng **hiện tại thuộc nhóm Administrators**.
Nếu dùng Standard User, dù bypass được UAC, vẫn không có token Admin để dùng.

### 6.3 Bật Windows Defender Credential Guard

```powershell
# Kiểm tra trạng thái
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Bật qua Group Policy:
# Computer Configuration → Administrative Templates →
# System → Device Guard → Turn on Virtualization Based Security
```

### 6.4 Cấu hình AppLocker hoặc WDAC

**AppLocker** cho phép chỉ định chính xác **chương trình nào được phép chạy**:

```powershell
# Tạo policy AppLocker mặc định (chỉ cho phép Windows + Program Files)
# Mở gpedit.msc → Computer Configuration →
#   Windows Settings → Security Settings →
#   Application Control Policies → AppLocker

# Hoặc dùng PowerShell:
# Set-AppLockerPolicy -PolicyFilePath "path\to\policy.xml" -Merge
```

**Hiệu quả đặc biệt cho PoC này:**
`ConsoleApp1.exe` nằm ở `C:\update\` — một thư mục KHÔNG nằm trong danh sách tin cậy.
AppLocker sẽ **chặn ngay** khi nó cố chạy.

### 6.5 Giám sát thư mục staging

```powershell
# Tạo File System Watcher cho thư mục C:\update\
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher "Created" -Action {
    $path = $Event.SourceEventArgs.FullPath
    if ($path -like "*.exe" -or $path -like "*.dll") {
        Write-Host "[ALERT] File thực thi mới: $path" -ForegroundColor Red
        # Có thể gửi email/Slack thông báo ở đây
    }
}
```

### 6.6 Group Policy: Chặn các chương trình auto-elevated thường bị lợi dụng

```
Computer Configuration → Windows Settings → Security Settings →
Software Restriction Policies → Additional Rules

Thêm rule cho:
- C:\Windows\System32\fodhelper.exe → Disallowed
- C:\Windows\System32\ComputerDefaults.exe → Disallowed
  (Nếu tổ chức không dùng các chương trình này)
```

### 6.7 Bảng tổng hợp biện pháp phòng ngừa

| Biện pháp | Độ khó | Hiệu quả | Ghi chú |
|-----------|--------|-----------|---------|
| UAC ở mức cao nhất | ⭐ Dễ | Cao | Không chặn 100%, nhưng giảm rủi ro đáng kể |
| Dùng Standard User | ⭐ Dễ | Rất cao | Biện pháp hiệu quả nhất |
| AppLocker / WDAC | ⭐⭐ Trung bình | Rất cao | Cần cấu hình cẩn thận |
| Sysmon monitoring | ⭐⭐ Trung bình | Cao | Phát hiện nhanh, không ngăn chặn |
| Credential Guard | ⭐⭐⭐ Khó | Cao | Yêu cầu phần cứng hỗ trợ |
| EDR Solution | ⭐⭐⭐ Khó | Rất cao | Tốn chi phí, phù hợp doanh nghiệp |

---

## 7. Kịch bản E — Giám sát liên tục với Sysmon

### 7.1 Sysmon là gì?

**Sysmon** (System Monitor) là công cụ miễn phí của Microsoft, ghi lại chi tiết
mọi hoạt động trên hệ thống: tạo tiến trình, kết nối mạng, đọc/ghi registry...

Nó giống như **camera giám sát** cho hệ điều hành.

### 7.2 Cài đặt Sysmon

```powershell
# Tải Sysmon từ Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Cài đặt với config cơ bản
sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 7.3 Sysmon config tối ưu cho UAC Bypass

```xml
<!-- sysmon-uac-config.xml -->
<Sysmon schemaversion="4.90">
    <EventFiltering>
        <!-- Event ID 1: Ghi log TẤT CẢ process creation -->
        <ProcessCreate onmatch="include">
            <!-- Log khi auto-elevated binary được chạy -->
            <Image condition="end with">fodhelper.exe</Image>
            <Image condition="end with">eventvwr.exe</Image>
            <Image condition="end with">ComputerDefaults.exe</Image>
            <Image condition="end with">winver.exe</Image>
            <Image condition="end with">sdclt.exe</Image>
            <Image condition="end with">slui.exe</Image>

            <!-- Log khi chạy từ thư mục đáng ngờ -->
            <Image condition="contains">\update\</Image>
            <Image condition="contains">\temp\</Image>
            <Image condition="contains">\Users\</Image>

            <!-- Log khi integrity level là High/System mà parent bất thường -->
            <IntegrityLevel condition="is">High</IntegrityLevel>
            <IntegrityLevel condition="is">System</IntegrityLevel>

            <!-- Log khi có parent process spoofing indicators -->
            <ParentImage condition="end with">ComputerDefaults.exe</ParentImage>
            <ParentImage condition="end with">fodhelper.exe</ParentImage>
        </ProcessCreate>

        <!-- Event ID 3: Log kết nối mạng từ tiến trình đáng ngờ -->
        <NetworkConnect onmatch="include">
            <Image condition="contains">\update\</Image>
            <Image condition="contains">\temp\</Image>
            <DestinationPort condition="is">4444</DestinationPort>
            <DestinationPort condition="is">4443</DestinationPort>
            <DestinationPort condition="is">8080</DestinationPort>
            <DestinationPort condition="is">8443</DestinationPort>
        </NetworkConnect>

        <!-- Event ID 13: Log thay đổi registry liên quan UAC bypass -->
        <RegistryEvent onmatch="include">
            <TargetObject condition="contains">ms-settings\shell\open\command</TargetObject>
            <TargetObject condition="contains">mscfile\shell\open\command</TargetObject>
        </RegistryEvent>

        <!-- Event ID 11: Log file mới tạo trong thư mục đáng ngờ -->
        <FileCreate onmatch="include">
            <TargetFilename condition="contains">\update\</TargetFilename>
            <TargetFilename condition="end with">.exe</TargetFilename>
        </FileCreate>
    </EventFiltering>
</Sysmon>
```

### 7.4 Đọc log Sysmon

```powershell
# Xem 20 event mới nhất từ Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message | Format-List

# Tìm process creation events (Event ID 1) có liên quan đến auto-elevated binary
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 } |
    Where-Object { $_.Message -match "ComputerDefaults|fodhelper|eventvwr|winver" } |
    Select-Object TimeCreated, Message

# Tìm kết nối mạng đáng ngờ (Event ID 3)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 3 } |
    Where-Object { $_.Message -match "4444|update\\\\ConsoleApp" } |
    Select-Object TimeCreated, Message
```

---

## 8. Kịch bản F — Phân tích hành vi trong Sandbox

### 8.1 Sandbox là gì?

**Sandbox** là một môi trường ảo **cô lập** để chạy file đáng ngờ mà không ảnh hưởng máy thật.
Giống như **phòng thí nghiệm cách ly** — bạn cho virus vào đó để nghiên cứu an toàn.

### 8.2 Sandbox miễn phí

| Sandbox | Loại | Link |
|---------|------|------|
| Windows Sandbox | Tích hợp Windows 10/11 Pro | Bật trong Windows Features |
| ANY.RUN | Online, tương tác được | https://any.run |
| Hybrid Analysis | Online, tự động | https://hybrid-analysis.com |
| Joe Sandbox | Online, chi tiết | https://www.joesandbox.com |
| Triage | Online, tự động | https://tria.ge |

### 8.3 Những gì sandbox cho thấy với PoC này

Khi chạy `test.exe` trong sandbox, ta sẽ thấy:

| Hành vi | Chi tiết | Mức cảnh báo |
|---------|----------|--------------|
| Process creation chain | `test.exe` → `winver.exe` → `ComputerDefaults.exe` → `ConsoleApp1.exe` | 🔴 Cao |
| Privilege escalation | `ConsoleApp1.exe` chạy với integrity "High" | 🔴 Cao |
| Memory allocation | `VirtualAlloc` với quyền RWX | 🔴 Cao |
| Network connection | Kết nối outbound đến port 4444 | 🔴 Rất cao |
| Registry access | Đọc/ghi AppInfo-related keys | 🟡 Trung bình |

### 8.4 Dùng Windows Sandbox

```powershell
# Bật Windows Sandbox (chạy 1 lần)
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart

# Sau đó mở: Start Menu → "Windows Sandbox"
# Copy file nghi ngờ vào sandbox và chạy
# Dùng Process Monitor/Process Explorer để theo dõi
```

---

## 9. Tổng hợp công cụ BlueTeamDetector

### 9.1 Kiến trúc công cụ

```
BlueTeamDetector/
├── Program.cs              ← Entry point, xử lý CLI
├── CliOptions.cs           ← Parse tham số command line
├── Analysis/
│   ├── DetectionFinding.cs ← Cấu trúc dữ liệu kết quả
│   ├── RepoScanner.cs      ← Quét source code tìm IOC
│   ├── EventLogAnalyzer.cs ← Quét log Sysmon mô phỏng
│   └── BinaryAnalyzer.cs   ← [MỚI] Quét file .exe/.dll
├── Reporting/
│   ├── ConsoleReportWriter  ← In báo cáo ra terminal
│   └── JsonReportWriter     ← Xuất báo cáo JSON
├── samples/
│   ├── sample-sysmon-events.json  ← Log mẫu để demo
│   └── demo-report.json           ← Báo cáo mẫu
└── yara-rules/
    └── uac-bypass.yar      ← [MỚI] YARA rules

Công cụ bổ sung:
├── analyze_binary.py       ← [MỚI] Script phân tích PE
├── remediation-scan.ps1    ← [MỚI] Script gỡ mã độc
└── sysmon-uac-config.xml   ← [MỚI] Config Sysmon
```

### 9.2 Cách sử dụng

```bash
# Chế độ 1: Quét source code
dotnet run -- scan-repo /path/to/suspicious/repo

# Chế độ 2: Quét log Sysmon mô phỏng
dotnet run -- scan-events samples/sample-sysmon-events.json

# Chế độ 3: Demo đầy đủ (cả source + log)
dotnet run -- demo

# Chế độ 4: Quét file binary (MỚI)
dotnet run -- scan-binary /path/to/suspicious.exe

# Xuất JSON report
dotnet run -- demo --json report.json
```

### 9.3 Các rule phát hiện

| Rule ID | Nguồn | Ý nghĩa |
|---------|-------|---------|
| SRC-UAC-001 | Source scan | AppInfo RPC abuse indicators |
| SRC-UAC-002 | Source scan | Parent process spoofing + payload staging |
| SRC-MEM-001 | Source scan | Shellcode runner pattern |
| SRC-MEM-002 | Source scan | RWX memory allocation |
| SRC-OBF-001 | Source scan | XOR obfuscation markers |
| SRC-C2-001 | Source scan | Reverse shell IOC |
| EVT-UAC-001 | Event log | Auto-elevated binary in process chain |
| EVT-UAC-002 | Event log | Elevated payload from suspicious path |
| EVT-REG-001 | Event log | Registry UAC hijack key modified |
| EVT-C2-001 | Event log | Outbound connection from staged payload |
| EVT-UAC-003 | Event log | Correlated attack chain (Critical) |
| BIN-IMP-001 | Binary scan | Suspicious API import combination |
| BIN-ENT-001 | Binary scan | High entropy section (encrypted data) |
| BIN-STR-001 | Binary scan | Suspicious strings in binary |

---

## 10. Bảng tham chiếu nhanh

### Tôi nên làm gì khi...

| Tình huống | Kịch bản | Hành động đầu tiên |
|-----------|---------|-------------------|
| Có source code malware | A (Mục 3) | Trích xuất IOC, tạo YARA rule |
| Chỉ có file .exe đáng ngờ | B (Mục 4) | Hash → VirusTotal → Import table → Entropy |
| Mã độc đã chạy trên máy | C (Mục 5) | Ngắt mạng → Kill process → Dọn dẹp |
| Muốn phòng ngừa từ trước | D (Mục 6) | UAC mức cao + Standard User + AppLocker |
| Muốn giám sát liên tục | E (Mục 7) | Cài Sysmon + config |
| Cần phân tích file an toàn | F (Mục 8) | Dùng sandbox |

### Công cụ cần thiết

| Công cụ | Mục đích | Link/Cách cài |
|---------|---------|---------------|
| Sysmon | Giám sát hệ thống | Sysinternals Suite |
| YARA | Quét mã độc theo pattern | https://virustotal.github.io/yara/ |
| pestudio | Phân tích PE file | https://www.winitor.com |
| Process Explorer | Xem chi tiết tiến trình | Sysinternals Suite |
| Process Monitor | Theo dõi hoạt động real-time | Sysinternals Suite |
| Autoruns | Kiểm tra persistence | Sysinternals Suite |
| VirusTotal | Tra hash online | https://www.virustotal.com |
| BlueTeamDetector | Công cụ trong dự án này | `dotnet run -- demo` |

---

## Phụ lục A: Thuật ngữ

| Thuật ngữ | Giải thích |
|-----------|-----------|
| **UAC** | User Account Control — Cơ chế kiểm soát quyền truy cập của Windows |
| **Privilege Escalation** | Leo thang đặc quyền — Từ quyền thường lên quyền Admin |
| **Reverse Shell** | Kết nối từ máy nạn nhân ngược về máy attacker |
| **Shellcode** | Đoạn mã nhị phân nhỏ, thường dùng sau khi khai thác lỗ hổng |
| **IOC** | Indicator of Compromise — Dấu hiệu bị xâm nhập |
| **YARA** | Công cụ tạo rule quét mã độc dựa trên pattern |
| **Entropy** | Mức độ ngẫu nhiên của dữ liệu, entropy cao = có thể bị mã hóa |
| **PE File** | Portable Executable — Định dạng file .exe/.dll trên Windows |
| **Import Table** | Bảng liệt kê API mà chương trình sử dụng |
| **Sysmon** | System Monitor — Ghi log chi tiết hoạt động hệ thống |
| **Sandbox** | Môi trường cô lập để chạy file đáng ngờ an toàn |
| **EDR** | Endpoint Detection and Response — Giải pháp bảo vệ endpoint |
| **ETW** | Event Tracing for Windows — Hệ thống ghi log của Windows |
| **RWX** | Read-Write-Execute — Quyền bộ nhớ cho phép đọc, ghi, và thực thi |
| **Auto-elevated** | Chương trình Windows được phép tự nâng quyền không cần hỏi UAC |
| **Integrity Level** | Mức tin cậy: Low < Medium < High < System |

## Phụ lục B: Tham khảo MITRE ATT&CK

| ID | Tên | URL |
|----|-----|-----|
| T1548.002 | Bypass User Account Control | https://attack.mitre.org/techniques/T1548/002/ |
| T1027 | Obfuscated Files or Information | https://attack.mitre.org/techniques/T1027/ |
| T1055 | Process Injection | https://attack.mitre.org/techniques/T1055/ |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |
| T1071 | Application Layer Protocol (C2) | https://attack.mitre.org/techniques/T1071/ |
