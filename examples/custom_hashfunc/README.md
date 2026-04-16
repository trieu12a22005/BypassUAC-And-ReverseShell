# Custom Hash

Acheron cho phép truyền một hàm hash tùy chỉnh vào constructor, để nó có thể được sử dụng để lưu trữ và lấy các struct syscall từ map của chúng để có OPSEC tốt hơn.

Trong ví dụ này, hàm tùy chỉnh XOR buffer chuỗi với key `0xdeadbeef`, và chạy kết quả vào hàm hash SHA1.

Compile với:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o custom_hash.exe main.go
```
