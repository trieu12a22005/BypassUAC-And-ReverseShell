# sc_inject

PoC injector shellcode cực kỳ đơn giản, inject shellcode calc sử dụng syscalls cho `NtAllocateVirtualMemory`+`NtWriteVirtualMemory`+`NtCreateThreadEx`.

Sử dụng build tags, bạn có thể compile cả phiên bản direct và indirect syscall của injector, nếu bạn muốn chạy chúng chống lại các công cụ phòng thủ để kiểm tra phát hiện và so sánh IOCs của từng kỹ thuật.

```bash
# phiên bản indirect syscall (mặc định)
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o sc_inject_indirect.exe

# phiên bản direct syscall
GOOS=windows GOARCH=amd64 go build -tags='direct' -ldflags "-s -w" -o sc_inject_direct.exe
```
