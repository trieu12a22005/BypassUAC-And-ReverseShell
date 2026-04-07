# Phân tích Blue Team: UAC Bypass và Thực thi Payload trong Bộ nhớ

## 1. Mục tiêu

Tài liệu này được viết theo góc nhìn phòng thủ nhằm phân tích PoC trong repo hiện tại và trả lời ba câu hỏi:

1. Mã nguồn này đang mô phỏng kỹ thuật gì.
2. Dấu hiệu nào trong mã nguồn cho thấy kỹ thuật đó đang được sử dụng.
3. Blue team nên thu thập telemetry gì và phát hiện ra sao mà không cần chạy malware thật trên máy nạn nhân.

Phần trọng tâm của tài liệu là chỉ ra rõ:

- Hành vi nào xuất hiện trong `test.c`
- Hành vi nào xuất hiện trong `ConsoleApp1/Program.cs`
- Hành vi nào được chuẩn bị bởi `xor_encrypt.py`
- Dòng mã nào thể hiện từng hành vi đó

## 2. Tổng quan kỹ thuật

Repo này mô phỏng một chuỗi tấn công gồm hai thành phần chính:

| Thành phần | Vai trò | Mô tả ngắn |
| --- | --- | --- |
| `test.c` | Bộ khởi chạy leo thang đặc quyền | Thực hiện chuỗi UAC bypass để tạo tiến trình payload với quyền cao |
| `ConsoleApp1/Program.cs` | Shellcode runner | Giải mã shellcode, cấp phát vùng nhớ thực thi, chép shellcode vào bộ nhớ, tạo thread để chạy |
| `xor_encrypt.py` | Công cụ chuẩn bị payload | XOR-encode shellcode thô để nhúng vào chương trình C# |

Nếu nhìn toàn bộ chuỗi hành vi, PoC này thể hiện:

1. Tiến trình ban đầu chạy với quyền thường.
2. Tận dụng cơ chế liên quan đến AppInfo và tiến trình auto-elevated để có ngữ cảnh quyền cao.
3. Spawn `ConsoleApp1.exe` với quyền Administrator.
4. Giải XOR shellcode và thực thi nó trong bộ nhớ bằng `VirtualAlloc` + `Marshal.Copy` + `CreateThread`.
5. Chuẩn bị cho hành vi reverse shell callback.

## 3. Ánh xạ MITRE ATT&CK

| Kỹ thuật | Mô tả | ATT&CK |
| --- | --- | --- |
| UAC Bypass | Lạm dụng cơ chế nâng quyền của Windows mà không hiện hộp thoại UAC theo cách thông thường | `T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control` |
| Obfuscation bằng XOR | Làm mờ payload trước khi nhúng | `T1027 - Obfuscated/Compressed Files and Information` |
| Thực thi mã trong bộ nhớ | Giải payload và chạy trực tiếp trong vùng nhớ thực thi | Có thể mô tả là `in-memory execution` trong báo cáo phòng thủ |
| Reverse shell / callback | Tạo kết nối ra ngoài từ tiến trình nạn nhân | Có thể gắn với hành vi C2 hoặc remote shell tùy cách nhóm trình bày |

## 4. Kiến trúc hoạt động của PoC

### 4.1 Chuỗi hoạt động mức cao

| Bước | Thành phần | Hành vi |
| --- | --- | --- |
| 1 | `test.c` | Tương tác với AppInfo RPC và các tiến trình auto-elevated |
| 2 | `test.c` | Dùng debug object / parent-process context để tạo payload elevated |
| 3 | `test.c` | Spawn `C:\update\ConsoleApp1.exe` với quyền cao |
| 4 | `Program.cs` | Giải XOR shellcode đã nhúng |
| 5 | `Program.cs` | Cấp phát vùng nhớ `RWX` |
| 6 | `Program.cs` | Chép shellcode vào vùng nhớ vừa cấp phát |
| 7 | `Program.cs` | Tạo thread để thực thi shellcode |
| 8 | `Program.cs` | Giữ tiến trình sống để payload có thời gian callback |

### 4.2 Ý nghĩa phòng thủ

Blue team không nên chỉ phát hiện một file hoặc một hash. Cần phát hiện theo chuỗi:

- Có tiến trình đáng ngờ cố leo thang đặc quyền
- Có payload elevated chạy từ đường dẫn bất thường
- Có dấu hiệu thực thi payload trong bộ nhớ
- Có outbound connection ngay sau đó

## 5. Phân tích mã nguồn theo từng file và từng dòng

## 5.1 Phân tích `test.c`

File này là thành phần mô phỏng phần leo thang đặc quyền.

### 5.1.1 Dòng mã then chốt và ý nghĩa

| Dòng mã | Nội dung / hành vi | Ý nghĩa |
| --- | --- | --- |
| `test.c:11` | `APPINFO_RPC` | Cho thấy chương trình chuẩn bị giao tiếp với cơ chế AppInfo |
| `test.c:13-14` | `winver.exe`, `ComputerDefaults.exe` | Dùng các binary Windows auto-elevated trong chuỗi UAC bypass |
| `test.c:55-75` | `RAiLaunchAdminProcess`, `AicLaunchAdminProcess` | Hàm bao việc gọi RPC để yêu cầu launch tiến trình với ngữ cảnh nâng quyền |
| `test.c:78-112` | `ucmxCreateProcessFromParent` | Tạo tiến trình payload dựa trên parent process được chỉ định |
| `test.c:90-93` | `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute` | Gắn `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, rất quan trọng trong việc kế thừa context tiến trình |
| `test.c:99-103` | `CreateProcessW` cho payload | Spawn payload `ConsoleApp1.exe` với quyền cao |
| `test.c:121-122` | `C:\update\ConsoleApp1.exe` | IOC rõ ràng để theo dõi payload elevated từ đường dẫn staging |
| `test.c:132-141` | Phase 1 với `winver.exe` | Tạo chuỗi lấy debug object từ tiến trình elevated |
| `test.c:143-150` | Phase 2 với `ComputerDefaults.exe` | Dùng tiến trình auto-elevated làm mắt xích tiếp theo |
| `test.c:152-167` | Vòng lặp debug event | Chờ thời điểm thích hợp để duplicate handle và tạo payload |
| `test.c:155-157` | `NtDuplicateObject` + `ucmxCreateProcessFromParent` | Bước quan trọng để chuyển sang tiến trình payload elevated |

### 5.1.2 Diễn giải theo luồng thực thi

1. Ở `test.c:11`, chương trình định nghĩa RPC interface `APPINFO_RPC`, đây là dấu hiệu cho thấy mã có liên quan đến AppInfo.
2. Ở `test.c:59-75`, hàm `AicLaunchAdminProcess` dựng RPC binding, thiết lập security QoS và gọi `RAiLaunchAdminProcess`.
3. Ở `test.c:132-141`, chương trình mở đầu bằng `winver.exe` trong chế độ debug để lấy debug object.
4. Ở `test.c:143-150`, chương trình chuyển sang `ComputerDefaults.exe`, một binary được dùng trong các kỹ thuật UAC bypass nổi tiếng.
5. Ở `test.c:152-167`, chương trình chờ debug event, lấy process handle và duplicate handle ở `test.c:155`.
6. Cuối cùng, ở `test.c:157`, payload `C:\update\ConsoleApp1.exe` được tạo bằng `ucmxCreateProcessFromParent`, nghĩa là payload được sinh ra trong ngữ cảnh đã được nâng quyền.

### 5.1.3 Giá trị phát hiện từ góc nhìn blue team

| Dấu hiệu | Giá trị phát hiện |
| --- | --- |
| `APPINFO_RPC` | Dấu hiệu source-level cho thấy kỹ thuật liên quan tới cơ chế nâng quyền của Windows |
| `winver.exe`, `ComputerDefaults.exe` | IOC hành vi trong process chain |
| `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | Chỉ báo tiến trình đang thao tác parent process bất thường |
| Payload hardcode `C:\update\ConsoleApp1.exe` | IOC trực tiếp để hunt tiến trình elevated từ đường dẫn lạ |

## 5.2 Phân tích `ConsoleApp1/Program.cs`

File này là shellcode runner, tức là phần thực thi payload trong bộ nhớ.

### 5.2.1 Dòng mã then chốt và ý nghĩa

| Dòng mã | Nội dung / hành vi | Ý nghĩa |
| --- | --- | --- |
| `Program.cs:9-10` | `XorKey` | Khóa XOR dùng để giải mã shellcode |
| `Program.cs:12-43` | `EncryptedShellcode` | Payload đã được mã hóa sẵn và nhúng trực tiếp |
| `Program.cs:45-53` | Import `VirtualAlloc`, `CreateThread`, `WaitForSingleObject` | Bộ API đặc trưng cho shellcode runner |
| `Program.cs:59-60` | `Decrypt(EncryptedShellcode)` | Bắt đầu giải payload ngay trong runtime |
| `Program.cs:63-64` | `VirtualAlloc(..., 0x3000, 0x40)` | Cấp phát vùng nhớ có quyền thực thi và ghi |
| `Program.cs:73-75` | `Marshal.Copy` | Chép shellcode vào vùng nhớ vừa cấp phát |
| `Program.cs:77-78` | `CreateThread` | Chạy shellcode trong một thread mới |
| `Program.cs:87-88` | Log liên quan listener `4444` | Dấu hiệu reverse shell callback |
| `Program.cs:90-91` | `WaitForSingleObject` | Giữ process sống để shellcode tiếp tục hoạt động |
| `Program.cs:95-101` | Hàm `Decrypt` | Thực hiện XOR decode trên từng byte |

### 5.2.2 Diễn giải theo luồng thực thi

1. `Program.cs:10` định nghĩa một XOR key cố định.
2. `Program.cs:13-43` chứa blob `EncryptedShellcode`, nghĩa là shellcode không được lưu dạng thô mà đã được làm mờ.
3. `Program.cs:60` gọi `Decrypt`, còn phần giải XOR thật nằm ở `Program.cs:97-100`.
4. `Program.cs:64` gọi `VirtualAlloc` với cờ `0x40`, tức `PAGE_EXECUTE_READWRITE`, là dấu hiệu rất mạnh của in-memory execution.
5. `Program.cs:74` dùng `Marshal.Copy` để chép bytes shellcode vào vùng nhớ vừa cấp phát.
6. `Program.cs:78` gọi `CreateThread`, truyền địa chỉ vùng nhớ vừa chép làm entry point.
7. `Program.cs:88` in ra `nc -lvnp 4444`, cho thấy mục tiêu của shellcode là callback hoặc reverse shell.
8. `Program.cs:91` giữ thread chạy vô thời hạn.

### 5.2.3 Giá trị phát hiện từ góc nhìn blue team

| Dấu hiệu | Giá trị phát hiện |
| --- | --- |
| `XorKey` + `EncryptedShellcode` | Chỉ báo obfuscation payload |
| `VirtualAlloc` + `RWX` | Chỉ báo thực thi mã trong bộ nhớ |
| `Marshal.Copy` | Dấu hiệu chép payload vào bộ nhớ mới cấp phát |
| `CreateThread` | Dấu hiệu chuyển payload sang trạng thái thực thi |
| Port `4444` | IOC phụ cho callback |

## 5.3 Phân tích `xor_encrypt.py`

File này không trực tiếp chạy payload, nhưng nó cho thấy cách tác giả chuẩn bị shellcode trước khi nhúng.

### 5.3.1 Dòng mã then chốt và ý nghĩa

| Dòng mã | Nội dung / hành vi | Ý nghĩa |
| --- | --- | --- |
| `xor_encrypt.py:4` | `KEY = [...]` | Khóa XOR giống khóa trong `Program.cs` |
| `xor_encrypt.py:7` | Comment `msfvenom ... shell_reverse_tcp` | Gợi ý rõ loại payload được tạo |
| `xor_encrypt.py:11-13` | Đọc raw shellcode từ file | Chuẩn bị đầu vào cho quá trình mã hóa |
| `xor_encrypt.py:21-23` | XOR từng byte | Thực hiện obfuscation |
| `xor_encrypt.py:26-36` | In ra `XorKey` và `EncryptedShellcode` | Sinh dữ liệu để paste vào chương trình khác |

### 5.3.2 Ý nghĩa phòng thủ

Từ góc nhìn blue team, file này chứng minh:

- Payload không phải ngẫu nhiên mà được chuẩn bị theo hướng reverse shell
- Obfuscation sử dụng XOR khóa cố định
- Dấu hiệu `XorKey`, `EncryptedShellcode`, `shell_reverse_tcp` là các IOC source-level rất hữu ích

## 6. Bảng đối chiếu: hành vi và bằng chứng mã nguồn

| Hành vi | Bằng chứng mã nguồn | Nhận xét blue team |
| --- | --- | --- |
| Tương tác với cơ chế AppInfo | `test.c:11`, `test.c:59-75` | Có thể xây rule source scan hoặc YARA cho mã PoC/lab |
| Dùng binary auto-elevated | `test.c:13-14`, `test.c:134-145` | Nên giám sát process chain có `winver.exe`, `ComputerDefaults.exe`, `fodhelper.exe`, `eventvwr.exe` |
| Parent-process manipulation | `test.c:90-93` | Dấu hiệu bất thường trong tiến trình tạo con |
| Spawn payload elevated | `test.c:99-103`, `test.c:157` | Có thể alert nếu child process quyền cao chạy từ `C:\update\` hoặc thư mục lạ |
| Obfuscation bằng XOR | `Program.cs:10`, `Program.cs:13`, `Program.cs:95-101`, `xor_encrypt.py:21-23` | Dễ đưa vào static rule |
| Cấp phát memory thực thi | `Program.cs:63-64` | Dấu hiệu mạnh cho shellcode runner |
| Chép payload vào memory | `Program.cs:73-75` | Cần correlate với `VirtualAlloc` |
| Tạo thread thực thi | `Program.cs:77-78` | Hoàn chỉnh chuỗi shellcode runner |
| Callback / reverse shell | `Program.cs:88`, `xor_encrypt.py:7` | IOC phụ để tăng độ tin cậy |

## 7. Telemetry nên thu thập

Ngay cả khi không được chạy malware trên máy thật, nhóm vẫn có thể mô tả rõ telemetry cần dùng:

| Telemetry | Nguồn | Mục đích |
| --- | --- | --- |
| Process Creation | Sysmon Event ID 1 hoặc Security 4688 | Theo dõi chain `test.exe -> winver.exe/ComputerDefaults.exe -> ConsoleApp1.exe` |
| Network Connection | Sysmon Event ID 3 | Theo dõi callback từ payload elevated |
| Registry Set | Sysmon Event ID 13 | Quan trọng nếu mở rộng bài sang biến thể `fodhelper.exe` hoặc `eventvwr.exe` |
| File Create | Sysmon Event ID 11 | Theo dõi payload xuất hiện tại `C:\update\` hoặc thư mục staging khác |
| Memory / EDR telemetry | EDR hoặc ETW | Theo dõi `RWX allocation`, `thread start`, `shellcode execution` |

## 8. Chiến lược phát hiện

## 8.1 Static detection trên source hoặc artifact

| Rule ID | Điều kiện | Giải thích |
| --- | --- | --- |
| `SRC-UAC-001` | Có `APPINFO_RPC`, `RAiLaunchAdminProcess`, `ComputerDefaults.exe`, `winver.exe` trong cùng file | Dấu hiệu rất mạnh cho PoC UAC bypass hiện tại |
| `SRC-UAC-002` | Có `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, `CreateProcessW`, `C:\update\ConsoleApp1.exe` | Dấu hiệu spawn payload elevated từ đường dẫn staging |
| `SRC-MEM-001` | Có `VirtualAlloc`, `Marshal.Copy`, `CreateThread` | Mẫu shellcode runner kinh điển |
| `SRC-MEM-002` | Có `VirtualAlloc` và `RWX` | Mẫu cấp phát vùng nhớ thực thi |
| `SRC-OBF-001` | Có `XorKey`, `EncryptedShellcode` | Dấu hiệu payload đã bị XOR hóa |
| `SRC-C2-001` | Có `shell_reverse_tcp`, `4444` | IOC phụ về callback |

## 8.2 Runtime correlation trên log

| Rule ID | Logic | Ý nghĩa |
| --- | --- | --- |
| `EVT-UAC-001` | Process chain chứa `winver.exe`, `ComputerDefaults.exe`, `fodhelper.exe`, `eventvwr.exe` | Dấu hiệu có thể liên quan UAC bypass |
| `EVT-UAC-002` | Child process `High` hoặc `System` chạy từ đường dẫn lạ | Dấu hiệu payload elevated bất thường |
| `EVT-C2-001` | Payload từ đường dẫn lạ tạo outbound connection | Dấu hiệu callback |
| `EVT-UAC-003` | Trong 2 phút xuất hiện auto-elevated binary, sau đó có payload elevated và network callback | Cảnh báo tương quan mức cao |

## 9. Thiết kế công cụ BlueTeamDetector trong repo

Tool blue team được viết để phục vụ demo an toàn, không cần chạy malware thật.

| Chế độ | Mục đích | File liên quan |
| --- | --- | --- |
| `scan-repo` | Quét source PoC để tìm IOC và behavioral pattern | `BlueTeamDetector/Analysis/RepoScanner.cs` |
| `scan-events` | Quét file JSON mô phỏng log Sysmon | `BlueTeamDetector/Analysis/EventLogAnalyzer.cs` |
| `demo` | Chạy cả hai và xuất báo cáo JSON | `BlueTeamDetector/Program.cs` |

### 9.1 Ý nghĩa của cách làm này

Ưu điểm của hướng này là:

- An toàn cho máy làm bài
- Vẫn thể hiện tư duy phát hiện kỹ thuật
- Có thể trình bày được cả static detection lẫn telemetry correlation
- Phù hợp với yêu cầu “viết công cụ có khả năng phát hiện kỹ thuật tương ứng”

## 10. Kịch bản demo an toàn

Nhóm có thể demo theo thứ tự sau:

1. Giới thiệu chuỗi tấn công bằng sơ đồ từ `test.c` sang `ConsoleApp1.exe`.
2. Mở `blue-team.md` để chỉ từng dòng mã quan trọng.
3. Chạy `scan-repo` để cho thấy detector nhận diện được:
   - UAC bypass indicators
   - Payload elevated từ đường dẫn lạ
   - Shellcode runner pattern
   - XOR obfuscation
4. Chạy `scan-events` với file log mẫu để cho thấy detector dựng được một alert `Critical`.
5. Mở file JSON report để chứng minh công cụ có thể xuất báo cáo máy đọc được.

## 11. Kết luận

Điểm mạnh của bài này không nằm ở việc “biết PoC là malware”, mà nằm ở việc chứng minh được:

- Vì sao đây là chuỗi `UAC bypass + in-memory execution`
- Dòng mã nào thể hiện từng hành vi
- Blue team nên thu telemetry nào
- Công cụ phát hiện có thể hoạt động ngay cả khi không chạy malware thật

Nếu nhóm muốn dùng tài liệu này làm báo cáo nộp, phần quan trọng nhất để trình bày là Mục 5 và Mục 6, vì hai phần đó cho thấy rõ bằng chứng kỹ thuật và lập luận phòng thủ.
