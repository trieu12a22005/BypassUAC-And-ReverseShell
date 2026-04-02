# BypassUAC-And-ReverseShell

**UAC Bypass (Method 59) + Reverse Shell (tách 2 malware)**

Project này sử dụng **2 malware riêng biệt**:
- Malware 1: UAC Bypass (`test.exe`)
- Malware 2: Shellcode Runner (`ConsoleApp1.exe`)

Khi chạy Malware 1, nó sẽ bypass UAC và spawn Malware 2 với **quyền ADMIN**.

---

## 📁 Cấu trúc Project

| File / Thư mục         | Vai trò                                      |
|------------------------|----------------------------------------------|
| `test.c`               | Malware 1 - UAC Bypass (Method 59)           |
| `ConsoleApp1/`         | Malware 2 - C# Shellcode Runner              |
| `ConsoleApp1.exe`      | File exe đã compile của Malware 2            |
| `xor_encrypt.py`       | Tool encrypt shellcode (nếu muốn thay đổi)   |

---

## 🚀 Hướng dẫn sử dụng (Tách 2 file)

### Bước 1: Chuẩn bị Malware 2 (ConsoleApp1.exe)

- File `ConsoleApp1.exe` nằm sẵn trong thư mục `C:\update\ConsoleApp1.exe`
- Đây là file chạy shellcode (đã decrypt XOR và inject vào memory)
- **Không cần compile lại** nếu bạn chưa thay đổi shellcode

> **Lưu ý**: Đường dẫn này đã được hardcode trong `test.c`. Nếu bạn di chuyển file, phải sửa lại trong `test.c`.

### Bước 2: Compile Malware 1 (UAC Bypass)

Mở Command Prompt (x64) và chạy lệnh:

```cmd
cl test.c /W0 /nologo /O2 /MT /DWIN32_LEAN_AND_MEAN
→ Sẽ sinh ra file test.exe
Bước 3: Chạy tấn công

Trên máy attacker: Mở listenerBashnc -lvnp 4444
Copy 2 file sau vào máy victim:
test.exe (Malware 1)
ConsoleApp1.exe (Malware 2) → phải để đúng đường dẫn C:\update\ConsoleApp1.exe

Chạy test.exe với quyền bình thường (medium integrity)

Kết quả mong đợi:

UAC được bypass tự động
ConsoleApp1.exe sẽ được spawn với quyền ADMIN
Shellcode chạy → reverse shell callback về attacker với quyền Administrator


✅ Kiểm tra thành công

Trên máy victim: Mở Task Manager → kiểm tra ConsoleApp1.exe phải chạy với quyền Administrator
Trên máy attacker: Nhận được shell với quyền admin (whoami phải là nt authority\system hoặc user thuộc Administrators)


⚠️ Lưu ý quan trọng

Hai file phải nằm đúng vị trí (ConsoleApp1.exe ở C:\update\)
Windows Defender có thể detect nếu shellcode chưa obfuscate mạnh
Chỉ dùng cho mục đích học tập và pentest hợp pháp
Folder ConsoleApp1 chứa source C# của Malware 2 (dùng để chỉnh sửa nếu cần)


Nếu bạn muốn:

Thay đổi đường dẫn ConsoleApp1.exe
Thay shellcode mới
Làm cho 2 file ít bị detect hơn

Cứ nói mình chỉnh code và README tiếp nhé!
Tác giả: trieu12a22005
