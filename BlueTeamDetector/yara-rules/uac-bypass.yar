/*
    YARA Rules - Phát hiện UAC Bypass và Shellcode Runner
    Dự án: BypassUAC-And-ReverseShell (Blue Team)
    Sử dụng: yara -r uac-bypass.yar /path/to/scan/
*/

// === RULE 1: Phát hiện ConsoleApp1 shellcode runner dựa trên XOR key đã biết ===
rule Known_XOR_ShellcodeRunner {
    meta:
        description = "Phat hien ConsoleApp1 shellcode runner voi XOR key da biet"
        author = "BlueTeam"
        mitre = "T1548.002, T1027"
        severity = "Critical"
        date = "2026-04-15"

    strings:
        $xor_key = { AA BB CC DD EE FF 11 22 }
        $enc_head = { 56 F3 4F 39 1E 17 D1 22 AA BB 8D 8C AF AF 43 73 }
        $s1 = "ShellcodeRunner" ascii wide nocase
        $s2 = "Shellcode decrypted" ascii wide
        $s3 = "nc -lvnp 4444" ascii wide

    condition:
        $xor_key or $enc_head or (2 of ($s*))
}

// === RULE 2: Phát hiện pattern shellcode runner tổng quát ===
rule Generic_Shellcode_Runner {
    meta:
        description = "Phat hien shellcode runner pattern chung trong binary"
        author = "BlueTeam"
        mitre = "T1055, T1059"
        severity = "High"

    strings:
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "CreateThread" ascii wide
        $api3 = "VirtualProtect" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "WaitForSingleObject" ascii wide
        $api6 = "VirtualAllocEx" ascii wide
        $api7 = "CreateRemoteThread" ascii wide

        // Shellcode headers pho bien (x64)
        $sc64_1 = { FC 48 83 E4 F0 }
        $sc64_2 = { FC E8 ?? 00 00 00 }

        // Shellcode headers (x86)
        $sc32_1 = { FC E8 82 00 00 00 }
        $sc32_2 = { D9 EB 9B D9 74 24 }

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($api*)) or
            any of ($sc*) or
            ($api1 and $api2 and $api5)
        )
}

// === RULE 3: Phát hiện UAC Bypass indicators trong binary ===
rule UAC_Bypass_Indicators {
    meta:
        description = "Phat hien cac dau hieu UAC bypass trong file binary"
        author = "BlueTeam"
        mitre = "T1548.002"
        severity = "High"

    strings:
        // AppInfo RPC GUID
        $rpc_guid = "201ef99a-7fa0-444c-9399-19ba84f12a1a" ascii wide

        // Auto-elevated binaries
        $bin1 = "ComputerDefaults" ascii wide nocase
        $bin2 = "fodhelper" ascii wide nocase
        $bin3 = "eventvwr" ascii wide nocase
        $bin4 = "sdclt" ascii wide nocase
        $bin5 = "slui" ascii wide nocase

        // UAC bypass APIs
        $api1 = "NtDuplicateObject" ascii
        $api2 = "NtQueryInformationProcess" ascii
        $api3 = "NtRemoveProcessDebug" ascii
        $api4 = "DbgUiSetThreadDebugObject" ascii

        // Registry keys used in bypass
        $reg1 = "ms-settings\\shell\\open\\command" ascii wide nocase
        $reg2 = "mscfile\\shell\\open\\command" ascii wide nocase

        // Parent process spoofing
        $spoof1 = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" ascii
        $spoof2 = "InitializeProcThreadAttributeList" ascii
        $spoof3 = "UpdateProcThreadAttribute" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            $rpc_guid or
            ($api1 and $api2) or
            ($api3 and $api4) or
            (any of ($bin*) and any of ($reg*)) or
            (2 of ($spoof*) and any of ($api*))
        )
}

// === RULE 4: .NET shellcode runner (nhu ConsoleApp1) ===
rule DotNet_Shellcode_Runner {
    meta:
        description = "Phat hien .NET binary voi P/Invoke shellcode runner pattern"
        author = "BlueTeam"
        mitre = "T1055"
        severity = "Critical"

    strings:
        $dotnet1 = "mscoree.dll" ascii wide nocase
        $dotnet2 = "_CorExeMain" ascii

        $pinvoke1 = "DllImport" ascii wide
        $pinvoke2 = "kernel32" ascii wide nocase
        $pinvoke3 = "ntdll" ascii wide nocase

        $api1 = "VirtualAlloc" ascii wide
        $api2 = "CreateThread" ascii wide
        $api3 = "Marshal" ascii wide
        $api4 = "Copy" ascii wide

        $mem = "PAGE_EXECUTE" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        any of ($dotnet*) and
        any of ($pinvoke*) and
        (
            ($api1 and $api2) or
            ($api1 and $api3 and $api4) or
            $mem
        )
}

// === RULE 5: XOR encoded payload ===
rule XOR_Encoded_Payload {
    meta:
        description = "Phat hien dau hieu XOR encoding trong binary"
        author = "BlueTeam"
        mitre = "T1027"
        severity = "Medium"

    strings:
        $s1 = "XorKey" ascii wide nocase
        $s2 = "EncryptedShellcode" ascii wide nocase
        $s3 = "xor_encrypt" ascii wide nocase
        $s4 = "Decrypt" ascii wide
        $s5 = "xor_key" ascii wide nocase
        $s6 = "encrypted" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($s*))
}

// === RULE 6: Reverse shell indicators ===
rule Reverse_Shell_Indicators {
    meta:
        description = "Phat hien dau hieu reverse shell trong binary"
        author = "BlueTeam"
        mitre = "T1059"
        severity = "High"

    strings:
        $s1 = "shell_reverse_tcp" ascii wide nocase
        $s2 = "meterpreter" ascii wide nocase
        $s3 = "reverse_https" ascii wide nocase
        $s4 = "reverse_http" ascii wide nocase
        $s5 = "LHOST=" ascii wide
        $s6 = "LPORT=" ascii wide
        $s7 = "nc -lvnp" ascii wide
        $s8 = "cmd.exe /c" ascii wide
        $s9 = "powershell -e" ascii wide nocase

        $port1 = "4444" ascii wide
        $port2 = "4443" ascii wide
        $port3 = "1337" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($s*) or
            (2 of ($port*))
        )
}
