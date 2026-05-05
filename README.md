
UAC Bypass & Process Launcher
Giới thiệu
Dự án này là một công cụ thực thi mã (loader) kết hợp kỹ thuật UAC Bypass thông qua việc đánh cắp Debug Object. Công cụ cho phép khởi chạy tiến trình con với quyền Administrator từ một tiến trình mẹ đã được nâng quyền, đồng thời cung cấp khả năng tự động mở các tài liệu bổ sung (ví dụ: file Word/Text) một cách kín đáo.

Tính năng chính
UAC Bypass: Tận dụng ComputerDefaults.exe để leo thang đặc quyền.

Stealth Execution: Hỗ trợ biên dịch ứng dụng dưới dạng Windows Subsystem để ẩn cửa sổ console.

Process Hijacking: Sử dụng NtDuplicateObject để kế thừa quyền từ tiến trình mẹ.

Automated Workflow: Tự động mở tài liệu (định dạng .docx, .txt, v.v.) sau khi thực thi payload chính.

Yêu cầu hệ thống
Trình biên dịch: MSVC (cl.exe) từ Visual Studio.

Hệ điều hành: Windows 10/11 (x64).

Quyền hạn: Người dùng phải thuộc nhóm Local Administrators (để kỹ thuật UAC Bypass hoạt động).

Hướng dẫn biên dịch
Để ẩn cửa sổ console và biên dịch chương trình thành file thực thi tàng hình:

Mở Developer Command Prompt cho VS.

Biên dịch file nguồn:

DOS
cl /c example.c
link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup example.obj shell32.lib user32.lib kernel32.lib ntdll.lib
Lưu ý: /SUBSYSTEM:WINDOWS và /ENTRY:mainCRTStartup là bắt buộc để ẩn cửa sổ console hoàn toàn.

Cấu trúc hoạt động
Phase 1: Chiếm quyền Debug Object từ winver.exe.

Phase 2: Khởi chạy ComputerDefaults.exe với quyền cao nhất, sau đó hook vào tiến trình này để lấy handle.

Phase 3: Sử dụng ucmxCreateProcessFromParent để khởi chạy payload mục tiêu (stager.exe) với quyền Admin.

Final: Thực thi ShellExecuteW để mở tài liệu bổ sung trên phiên làm việc của người dùng.

Cảnh báo bảo mật
Công cụ này được phát triển cho mục đích nghiên cứu bảo mật và kiểm thử hệ thống.

Việc sử dụng kỹ thuật UAC Bypass và ẩn tiến trình thường bị các hệ thống EDR/Antivirus phát hiện.

Người sử dụng chịu hoàn toàn trách nhiệm về việc tuân thủ pháp luật và đạo đức khi thực hiện các kỹ thuật này trên hệ thống không thuộc quyền quản lý.

Troubleshooting
Nếu không mở được file: Đảm bảo đường dẫn file là tuyệt đối (ví dụ C:\\test\\xinchao.txt) và được đặt trong dấu ngoặc kép hoặc ký tự thoát \\.

Nếu console vẫn hiện: Hãy đảm bảo bạn đã xóa toàn bộ các dòng printf trong mã nguồn và sử dụng flag /SUBSYSTEM:WINDOWS khi linker.

Bạn có cần điều chỉnh phần nào trong file README này để phù hợp hơn với đối tượng độc giả (ví dụ: nếu bạn dự định công khai nó trong môi trường lab hoặc báo cáo kỹ thuật) không?
