#!/usr/bin/env python3
"""
analyze_binary.py — Phân tích file PE để phát hiện dấu hiệu mã độc
Sử dụng: python3 analyze_binary.py <path_to_exe>

Không cần source code. Chỉ cần file .exe hoặc .dll.
Yêu cầu: Python 3.6+ (không cần thư viện ngoài)
"""

import sys
import os
import math
import hashlib
import struct
from collections import Counter

# ============================================================
# Danh sách API nghi ngờ
# ============================================================
SUSPICIOUS_APIS = {
    "critical": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
        "WriteProcessMemory", "NtWriteVirtualMemory",
        "NtDuplicateObject", "NtQueryInformationProcess",
        "NtRemoveProcessDebug", "DbgUiSetThreadDebugObject",
    ],
    "high": [
        "OpenProcess", "QueueUserAPC",
        "SetThreadContext", "GetThreadContext",
        "ResumeThread", "SuspendThread",
        "RpcStringBindingComposeW", "NdrAsyncClientCall",
        "WaitForSingleObject",
    ],
    "medium": [
        "CreateProcessW", "CreateProcessA",
        "WinHttpOpen", "InternetOpenA", "InternetOpenW",
        "URLDownloadToFile",
        "RegSetValueEx", "RegCreateKeyEx",
    ]
}

SUSPICIOUS_STRINGS = [
    "shell_reverse_tcp", "meterpreter", "reverse_https",
    "nc -lvnp", "LHOST=", "LPORT=",
    "ShellcodeRunner", "EncryptedShellcode", "XorKey",
    "APPINFO_RPC", "201ef99a-7fa0-444c-9399-19ba84f12a1a",
    "ComputerDefaults", "fodhelper", "eventvwr",
    "ms-settings\\shell\\open\\command",
    "mscfile\\shell\\open\\command",
    "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
    "PAGE_EXECUTE_READWRITE",
]

# ============================================================
# Hàm phân tích
# ============================================================

def compute_hashes(data: bytes) -> dict:
    """Tính hash SHA256, MD5, SHA1 của file."""
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }


def compute_entropy(data: bytes) -> float:
    """Tính entropy (0-8). Giá trị >= 7 = có thể bị mã hóa/packed."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_strings(data: bytes, min_len: int = 6) -> list:
    """Trích xuất chuỗi ASCII từ binary."""
    result = []
    current = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def extract_wide_strings(data: bytes, min_len: int = 6) -> list:
    """Trích xuất chuỗi Unicode (UTF-16LE) từ binary."""
    result = []
    current = []
    for i in range(0, len(data) - 1, 2):
        c = data[i] | (data[i + 1] << 8)
        if 0x20 <= c < 0x7F:
            current.append(chr(c))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def check_pe_header(data: bytes) -> dict:
    """Kiểm tra PE header cơ bản."""
    info = {
        "is_pe": False,
        "is_dotnet": False,
        "machine": "Unknown",
        "compile_time": None,
        "sections": [],
    }

    if len(data) < 64 or data[0:2] != b"MZ":
        return info

    info["is_pe"] = True

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data):
        return info

    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return info

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    info["machine"] = {0x14C: "x86", 0x8664: "x64"}.get(machine, f"0x{machine:X}")

    timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
    try:
        from datetime import datetime, timezone
        info["compile_time"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OSError, OverflowError):
        info["compile_time"] = f"Invalid ({timestamp})"

    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + optional_hdr_size

    for i in range(min(num_sections, 20)):
        off = section_offset + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        virt_size = struct.unpack_from("<I", data, off + 8)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]

        section_data = data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
        ent = compute_entropy(section_data) if section_data else 0.0

        is_exec = bool(chars & 0x20000000)
        is_write = bool(chars & 0x80000000)

        info["sections"].append({
            "name": name,
            "virtual_size": virt_size,
            "raw_size": raw_size,
            "entropy": round(ent, 2),
            "executable": is_exec,
            "writable": is_write,
            "rwx": is_exec and is_write,
        })

    # Check .NET
    strings = extract_strings(data[:min(len(data), 8192)], 4)
    info["is_dotnet"] = any("mscoree.dll" in s.lower() or "_CorExeMain" in s for s in strings)

    return info


def find_suspicious_apis(all_strings: list) -> dict:
    """Tìm API nghi ngờ trong danh sách strings."""
    found = {"critical": [], "high": [], "medium": []}
    for level, apis in SUSPICIOUS_APIS.items():
        for api in apis:
            if any(api in s for s in all_strings):
                found[level].append(api)
    return found


def find_suspicious_strings(all_strings: list) -> list:
    """Tìm chuỗi đáng ngờ."""
    found = []
    for marker in SUSPICIOUS_STRINGS:
        if any(marker.lower() in s.lower() for s in all_strings):
            found.append(marker)
    return found


def calculate_risk_score(pe_info, apis, sus_strings, overall_entropy, high_entropy_sections):
    """Tính điểm rủi ro tổng hợp (0-100)."""
    score = 0
    reasons = []

    # API imports
    crit_count = len(apis["critical"])
    if crit_count >= 3:
        score += 30
        reasons.append(f"{crit_count} critical API imports (+30)")
    elif crit_count >= 1:
        score += 15
        reasons.append(f"{crit_count} critical API imports (+15)")

    high_count = len(apis["high"])
    if high_count >= 2:
        score += 10
        reasons.append(f"{high_count} high-risk API imports (+10)")

    # Shellcode runner combo
    runner_apis = {"VirtualAlloc", "CreateThread", "WaitForSingleObject"}
    if runner_apis.issubset(set(apis["critical"]) | set(apis["high"])):
        score += 20
        reasons.append("Shellcode runner API combo detected (+20)")

    # UAC bypass combo
    uac_apis = {"NtDuplicateObject", "NtQueryInformationProcess"}
    if uac_apis.issubset(set(apis["critical"])):
        score += 20
        reasons.append("UAC bypass API combo detected (+20)")

    # Entropy
    if overall_entropy >= 7.0:
        score += 15
        reasons.append(f"High overall entropy {overall_entropy:.2f} (+15)")
    elif overall_entropy >= 6.0:
        score += 5
        reasons.append(f"Elevated entropy {overall_entropy:.2f} (+5)")

    # High entropy sections
    if high_entropy_sections:
        score += 10
        reasons.append(f"{len(high_entropy_sections)} high-entropy section(s) (+10)")

    # RWX sections
    rwx = [s for s in pe_info["sections"] if s["rwx"]]
    if rwx:
        score += 10
        reasons.append(f"{len(rwx)} RWX section(s) (+10)")

    # Suspicious strings
    str_count = len(sus_strings)
    if str_count >= 5:
        score += 15
        reasons.append(f"{str_count} suspicious strings (+15)")
    elif str_count >= 2:
        score += 8
        reasons.append(f"{str_count} suspicious strings (+8)")

    # .NET with P/Invoke → bonus
    if pe_info["is_dotnet"] and crit_count >= 2:
        score += 5
        reasons.append(".NET + critical P/Invoke (+5)")

    return min(score, 100), reasons


# ============================================================
# Main
# ============================================================

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def colorize(text, color):
    """ANSI color nếu terminal hỗ trợ."""
    colors = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m", "cyan": "\033[96m", "reset": "\033[0m"}
    if sys.stdout.isatty():
        return f"{colors.get(color, '')}{text}{colors['reset']}"
    return text


def main():
    if len(sys.argv) < 2:
        print("Sử dụng: python3 analyze_binary.py <file.exe>")
        print("  Phân tích file PE để phát hiện dấu hiệu mã độc.")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"[LỖI] File không tồn tại: {filepath}")
        sys.exit(1)

    print(f"\n  Binary Analyzer — Blue Team Tool")
    print(f"  File: {filepath}")
    print(f"  Size: {os.path.getsize(filepath):,} bytes")

    with open(filepath, "rb") as f:
        data = f.read()

    # 1. Hash
    print_section("1. FILE HASHES")
    hashes = compute_hashes(data)
    for algo, h in hashes.items():
        print(f"  {algo}: {h}")
    print(f"\n  Tra cứu: https://www.virustotal.com/gui/search/{hashes['SHA256']}")

    # 2. PE Header
    print_section("2. PE HEADER")
    pe_info = check_pe_header(data)
    if not pe_info["is_pe"]:
        print(colorize("  [!] File không phải PE (Portable Executable)", "yellow"))
        return

    print(f"  Architecture: {pe_info['machine']}")
    print(f"  .NET Assembly: {'Có' if pe_info['is_dotnet'] else 'Không'}")
    print(f"  Compile Time:  {pe_info['compile_time']}")
    print(f"  Sections:      {len(pe_info['sections'])}")

    # 3. Sections & Entropy
    print_section("3. SECTIONS & ENTROPY")
    overall_entropy = compute_entropy(data)
    print(f"  Overall entropy: {overall_entropy:.2f}/8.00", end="")
    if overall_entropy >= 7.0:
        print(colorize("  [CẢNH BÁO: Rất cao — có thể packed/encrypted]", "red"))
    elif overall_entropy >= 6.0:
        print(colorize("  [Chú ý: Hơi cao]", "yellow"))
    else:
        print(colorize("  [Bình thường]", "green"))

    high_ent_sections = []
    print(f"\n  {'Tên':<10} {'Kích thước':>10} {'Entropy':>10} {'Flags':>10}")
    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    for sec in pe_info["sections"]:
        flags = ""
        if sec["executable"]:
            flags += "X"
        if sec["writable"]:
            flags += "W"
        if sec["rwx"]:
            flags = colorize("RWX", "red")

        ent_str = f"{sec['entropy']:.2f}"
        if sec["entropy"] >= 7.0:
            ent_str = colorize(f"{sec['entropy']:.2f} !", "red")
            high_ent_sections.append(sec)
        elif sec["entropy"] >= 6.0:
            ent_str = colorize(f"{sec['entropy']:.2f}", "yellow")

        print(f"  {sec['name']:<10} {sec['raw_size']:>10,} {ent_str:>10} {flags:>10}")

    # 4. API Imports
    print_section("4. SUSPICIOUS API IMPORTS")
    all_strings = extract_strings(data, 4) + extract_wide_strings(data, 4)
    apis = find_suspicious_apis(all_strings)

    total_apis = sum(len(v) for v in apis.values())
    if total_apis == 0:
        print(colorize("  Không tìm thấy API nghi ngờ", "green"))
    else:
        for level, api_list in apis.items():
            if api_list:
                color = {"critical": "red", "high": "yellow", "medium": "cyan"}[level]
                print(f"  [{level.upper()}]:")
                for api in api_list:
                    print(f"    - {colorize(api, color)}")

    # 5. Suspicious Strings
    print_section("5. SUSPICIOUS STRINGS")
    sus_strings = find_suspicious_strings(all_strings)
    if not sus_strings:
        print(colorize("  Không tìm thấy chuỗi đáng ngờ", "green"))
    else:
        for s in sus_strings:
            print(f"    - {colorize(s, 'yellow')}")

    # 6. Risk Score
    print_section("6. RISK ASSESSMENT")
    score, reasons = calculate_risk_score(pe_info, apis, sus_strings, overall_entropy, high_ent_sections)

    if score >= 70:
        level_str = colorize(f"CRITICAL ({score}/100)", "red")
    elif score >= 40:
        level_str = colorize(f"HIGH ({score}/100)", "yellow")
    elif score >= 20:
        level_str = colorize(f"MEDIUM ({score}/100)", "cyan")
    else:
        level_str = colorize(f"LOW ({score}/100)", "green")

    print(f"\n  Điểm rủi ro: {level_str}")
    print(f"\n  Chi tiết:")
    for reason in reasons:
        print(f"    + {reason}")

    # 7. Recommendations
    print_section("7. KHUYẾN NGHỊ")
    if score >= 70:
        print("  1. CÁCH LY file ngay lập tức")
        print("  2. KHÔNG chạy file trên máy thật")
        print("  3. Upload lên VirusTotal để kiểm tra")
        print("  4. Phân tích trong sandbox (ANY.RUN, Hybrid Analysis)")
        print("  5. Nếu đã chạy: xem hướng dẫn gỡ bỏ trong huong-dan-phong-thu.md Mục 5")
    elif score >= 40:
        print("  1. Nên phân tích thêm trước khi chạy")
        print("  2. Upload lên VirusTotal")
        print("  3. Dùng sandbox nếu cần chạy thử")
    else:
        print("  1. Điểm rủi ro thấp, nhưng luôn cẩn thận với file không rõ nguồn gốc")
        print("  2. Có thể upload VirusTotal để xác nhận")

    print()


if __name__ == "__main__":
    main()
