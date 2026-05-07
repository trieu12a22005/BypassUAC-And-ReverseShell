using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace BlueTeamDetector.Analysis
{
    /// <summary>
    /// Phân tích file PE (exe/dll) để phát hiện dấu hiệu mã độc
    /// mà KHÔNG cần source code.
    /// </summary>
    internal sealed class BinaryAnalyzer
    {
        private static readonly string[] SuspiciousApiImports = new[]
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
            "WriteProcessMemory", "NtWriteVirtualMemory",
            "WaitForSingleObject", "WaitForMultipleObjects",
            "NtDuplicateObject", "NtQueryInformationProcess",
            "NtRemoveProcessDebug", "DbgUiSetThreadDebugObject",
            "RpcStringBindingComposeW", "RpcBindingFromStringBindingW",
            "NdrAsyncClientCall",
            "OpenProcess", "QueueUserAPC",
            "SetThreadContext", "GetThreadContext",
            "ResumeThread", "SuspendThread"
        };

        private static readonly string[] ShellcodeRunnerApis = new[]
        {
            "VirtualAlloc", "CreateThread", "WaitForSingleObject"
        };

        private static readonly string[] UacBypassApis = new[]
        {
            "NtDuplicateObject", "NtQueryInformationProcess", "CreateProcessW"
        };

        private static readonly string[] SuspiciousStrings = new[]
        {
            "shell_reverse_tcp", "meterpreter", "reverse_https",
            "nc -lvnp", "ncat", "LHOST=", "LPORT=",
            "ShellcodeRunner", "Shellcode", "shellcode",
            "EncryptedShellcode", "XorKey", "xor_key",
            "VirtualAlloc", "CreateThread",
            "APPINFO_RPC", "201ef99a-7fa0-444c-9399-19ba84f12a1a",
            "ComputerDefaults", "fodhelper", "eventvwr",
            "ms-settings\\shell\\open\\command",
            "mscfile\\shell\\open\\command",
            "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            "PAGE_EXECUTE_READWRITE",
            "ConsoleApp1", "update\\\\ConsoleApp"
        };

        public IReadOnlyList<DetectionFinding> Scan(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Binary not found: {filePath}");
            }

            var data = File.ReadAllBytes(filePath);
            var findings = new List<DetectionFinding>();

            if (!IsPeFile(data))
            {
                findings.Add(new DetectionFinding
                {
                    RuleId = "BIN-FMT-001",
                    Severity = Severity.Informational,
                    Title = "Not a PE file",
                    Technique = "N/A",
                    Description = "The file does not appear to be a valid PE (Portable Executable) file.",
                    Recommendation = "Verify the file format. It may be a script, archive, or corrupt binary.",
                    Score = 0
                });
                return findings;
            }

            findings.AddRange(AnalyzeImports(data, filePath));
            findings.AddRange(AnalyzeEntropy(data, filePath));
            findings.AddRange(AnalyzeStrings(data, filePath));
            findings.AddRange(AnalyzeHeaders(data, filePath));

            return findings;
        }

        private static bool IsPeFile(byte[] data)
        {
            if (data.Length < 64)
                return false;
            // Check MZ header
            return data[0] == 0x4D && data[1] == 0x5A;
        }

        private IReadOnlyList<DetectionFinding> AnalyzeImports(byte[] data, string filePath)
        {
            var findings = new List<DetectionFinding>();
            var text = ExtractAsciiStrings(data, 4);

            var foundApis = SuspiciousApiImports
                .Where(api => text.Any(s => s.Contains(api, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (foundApis.Count == 0)
                return findings;

            // Check for shellcode runner pattern
            var hasShellcodeRunner = ShellcodeRunnerApis.All(
                api => foundApis.Any(f => f.Equals(api, StringComparison.OrdinalIgnoreCase)));

            if (hasShellcodeRunner)
            {
                var finding = new DetectionFinding
                {
                    RuleId = "BIN-IMP-001",
                    Severity = Severity.Critical,
                    Title = "Shellcode runner API pattern detected in binary",
                    Technique = "In-memory execution",
                    Description = "Binary imports VirtualAlloc + CreateThread + WaitForSingleObject, the classic shellcode runner combination. This strongly suggests in-memory payload execution.",
                    Recommendation = "Quarantine immediately. Analyze in sandbox. Check for associated network connections.",
                    Score = 85
                };
                foreach (var api in ShellcodeRunnerApis.Where(a => foundApis.Contains(a)))
                {
                    finding.Evidence.Add(new EvidenceItem
                    {
                        Source = filePath,
                        Snippet = $"Import: {api}"
                    });
                }
                findings.Add(finding);
            }

            // Check for UAC bypass pattern
            var hasUacBypass = UacBypassApis.All(
                api => foundApis.Any(f => f.Equals(api, StringComparison.OrdinalIgnoreCase)));

            if (hasUacBypass)
            {
                var finding = new DetectionFinding
                {
                    RuleId = "BIN-IMP-002",
                    Severity = Severity.High,
                    Title = "UAC bypass API pattern detected in binary",
                    Technique = "T1548.002",
                    Description = "Binary imports NtDuplicateObject + NtQueryInformationProcess + CreateProcessW, consistent with debug object stealing UAC bypass technique.",
                    Recommendation = "Investigate process creation chains. Check parent process ancestry.",
                    Score = 75
                };
                foreach (var api in UacBypassApis.Where(a => foundApis.Contains(a)))
                {
                    finding.Evidence.Add(new EvidenceItem
                    {
                        Source = filePath,
                        Snippet = $"Import: {api}"
                    });
                }
                findings.Add(finding);
            }

            // General suspicious imports
            if (foundApis.Count >= 3 && !hasShellcodeRunner && !hasUacBypass)
            {
                var finding = new DetectionFinding
                {
                    RuleId = "BIN-IMP-003",
                    Severity = Severity.Medium,
                    Title = $"Multiple suspicious API imports ({foundApis.Count})",
                    Technique = "Various",
                    Description = $"Binary imports {foundApis.Count} APIs commonly associated with malicious activity: {string.Join(", ", foundApis.Take(5))}.",
                    Recommendation = "Review all imports and correlate with runtime behavior analysis.",
                    Score = 50
                };
                findings.Add(finding);
            }

            return findings;
        }

        private IReadOnlyList<DetectionFinding> AnalyzeEntropy(byte[] data, string filePath)
        {
            var findings = new List<DetectionFinding>();

            double overallEntropy = CalculateEntropy(data);

            if (overallEntropy >= 7.0)
            {
                findings.Add(new DetectionFinding
                {
                    RuleId = "BIN-ENT-001",
                    Severity = Severity.High,
                    Title = "Very high entropy indicates packed or encrypted content",
                    Technique = "T1027",
                    Description = $"Overall file entropy is {overallEntropy:F2}/8.0. Values above 7.0 strongly suggest the binary contains encrypted, compressed, or packed data — commonly used to hide malicious payloads.",
                    Recommendation = "Attempt unpacking. Analyze in sandbox to observe runtime decryption behavior.",
                    Score = 70,
                    Evidence = { new EvidenceItem { Source = filePath, Snippet = $"Overall entropy: {overallEntropy:F2}/8.0" } }
                });
            }
            else if (overallEntropy >= 6.0)
            {
                findings.Add(new DetectionFinding
                {
                    RuleId = "BIN-ENT-002",
                    Severity = Severity.Medium,
                    Title = "Elevated entropy may indicate obfuscated sections",
                    Technique = "T1027",
                    Description = $"Overall file entropy is {overallEntropy:F2}/8.0. Values between 6.0-7.0 may indicate partial encryption or compression of payload data.",
                    Recommendation = "Check individual PE sections for high-entropy regions. May contain embedded encrypted shellcode.",
                    Score = 40,
                    Evidence = { new EvidenceItem { Source = filePath, Snippet = $"Overall entropy: {overallEntropy:F2}/8.0" } }
                });
            }

            // Analyze chunks for high-entropy regions (possible embedded shellcode)
            int chunkSize = Math.Min(4096, data.Length);
            double maxChunkEntropy = 0;
            int maxChunkOffset = 0;

            for (int offset = 0; offset + chunkSize <= data.Length; offset += chunkSize)
            {
                var chunk = new byte[chunkSize];
                Array.Copy(data, offset, chunk, 0, chunkSize);
                double chunkEntropy = CalculateEntropy(chunk);
                if (chunkEntropy > maxChunkEntropy)
                {
                    maxChunkEntropy = chunkEntropy;
                    maxChunkOffset = offset;
                }
            }

            if (maxChunkEntropy >= 7.5 && overallEntropy < 7.0)
            {
                findings.Add(new DetectionFinding
                {
                    RuleId = "BIN-ENT-003",
                    Severity = Severity.High,
                    Title = "High-entropy region detected — possible embedded encrypted payload",
                    Technique = "T1027",
                    Description = $"A 4KB region at offset 0x{maxChunkOffset:X} has entropy {maxChunkEntropy:F2}/8.0, significantly higher than the overall file. This pattern is consistent with embedded encrypted shellcode.",
                    Recommendation = "Extract and analyze the high-entropy region. May contain XOR-encrypted payload.",
                    Score = 65,
                    Evidence = { new EvidenceItem { Source = filePath, Snippet = $"Offset 0x{maxChunkOffset:X}: entropy {maxChunkEntropy:F2}/8.0" } }
                });
            }

            return findings;
        }

        private IReadOnlyList<DetectionFinding> AnalyzeStrings(byte[] data, string filePath)
        {
            var findings = new List<DetectionFinding>();
            var allStrings = ExtractAsciiStrings(data, 6);
            var allWideStrings = ExtractWideStrings(data, 6);
            var combined = allStrings.Concat(allWideStrings).ToList();

            var matchedSuspicious = SuspiciousStrings
                .Where(s => combined.Any(cs => cs.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                .ToList();

            if (matchedSuspicious.Count >= 3)
            {
                var finding = new DetectionFinding
                {
                    RuleId = "BIN-STR-001",
                    Severity = Severity.High,
                    Title = $"Multiple suspicious strings found ({matchedSuspicious.Count})",
                    Technique = "Various",
                    Description = $"Binary contains {matchedSuspicious.Count} strings associated with malicious tools and UAC bypass techniques.",
                    Recommendation = "Cross-reference strings with known malware families. Analyze in sandbox.",
                    Score = 60
                };
                foreach (var s in matchedSuspicious.Take(5))
                {
                    finding.Evidence.Add(new EvidenceItem
                    {
                        Source = filePath,
                        Snippet = $"String match: \"{s}\""
                    });
                }
                findings.Add(finding);
            }
            else if (matchedSuspicious.Count >= 1)
            {
                var finding = new DetectionFinding
                {
                    RuleId = "BIN-STR-002",
                    Severity = Severity.Low,
                    Title = $"Suspicious string found: {matchedSuspicious.First()}",
                    Technique = "Various",
                    Description = $"Binary contains string(s) that may indicate malicious intent: {string.Join(", ", matchedSuspicious)}.",
                    Recommendation = "Investigate further. Single string matches may be false positives.",
                    Score = 20
                };
                findings.Add(finding);
            }

            return findings;
        }

        private IReadOnlyList<DetectionFinding> AnalyzeHeaders(byte[] data, string filePath)
        {
            var findings = new List<DetectionFinding>();

            if (data.Length < 64)
                return findings;

            // Check for .NET binary (CLR header)
            var strings = ExtractAsciiStrings(data, 4);
            bool isDotNet = strings.Any(s =>
                s.Contains("mscoree.dll", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("_CorExeMain", StringComparison.OrdinalIgnoreCase));

            if (isDotNet)
            {
                // .NET binaries with suspicious imports are esp. notable
                var hasMarshal = strings.Any(s => s.Contains("Marshal", StringComparison.OrdinalIgnoreCase));
                var hasDllImport = strings.Any(s => s.Contains("DllImport", StringComparison.OrdinalIgnoreCase));
                var hasInterop = strings.Any(s => s.Contains("InteropServices", StringComparison.OrdinalIgnoreCase));

                if (hasMarshal && (hasDllImport || hasInterop))
                {
                    findings.Add(new DetectionFinding
                    {
                        RuleId = "BIN-HDR-001",
                        Severity = Severity.Medium,
                        Title = ".NET binary with P/Invoke interop (potential shellcode runner)",
                        Technique = "In-memory execution",
                        Description = "This is a .NET assembly that uses P/Invoke (DllImport + Marshal), which is how .NET shellcode runners call native Windows APIs for memory allocation and thread creation.",
                        Recommendation = "Decompile with dnSpy or ILSpy. Check for VirtualAlloc/CreateThread P/Invoke calls.",
                        Score = 45,
                        Evidence = { new EvidenceItem { Source = filePath, Snippet = ".NET binary with Marshal + DllImport/InteropServices" } }
                    });
                }
            }

            // Check compilation timestamp
            if (data.Length >= 64)
            {
                int peOffset = BitConverter.ToInt32(data, 0x3C);
                if (peOffset > 0 && peOffset + 8 <= data.Length)
                {
                    if (data[peOffset] == 0x50 && data[peOffset + 1] == 0x45) // "PE"
                    {
                        uint timestamp = BitConverter.ToUInt32(data, peOffset + 8);
                        var compileTime = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime;

                        // Check for suspicious compile times (future or very old)
                        if (compileTime > DateTime.UtcNow.AddDays(1))
                        {
                            findings.Add(new DetectionFinding
                            {
                                RuleId = "BIN-HDR-002",
                                Severity = Severity.Medium,
                                Title = "PE timestamp is in the future — possible timestomping",
                                Technique = "T1070.006",
                                Description = $"Compile timestamp {compileTime:yyyy-MM-dd} is in the future, which may indicate timestamp manipulation to evade forensic analysis.",
                                Recommendation = "Treat with higher suspicion. Cross-reference with file system timestamps.",
                                Score = 35,
                                Evidence = { new EvidenceItem { Source = filePath, Snippet = $"PE TimeDateStamp: {compileTime:O}" } }
                            });
                        }
                    }
                }
            }

            return findings;
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;

            var freq = new int[256];
            foreach (byte b in data)
                freq[b]++;

            double entropy = 0;
            double len = data.Length;
            foreach (int f in freq)
            {
                if (f == 0) continue;
                double p = f / len;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        private static List<string> ExtractAsciiStrings(byte[] data, int minLength)
        {
            var results = new List<string>();
            var sb = new StringBuilder();

            foreach (byte b in data)
            {
                if (b >= 0x20 && b < 0x7F)
                {
                    sb.Append((char)b);
                }
                else
                {
                    if (sb.Length >= minLength)
                        results.Add(sb.ToString());
                    sb.Clear();
                }
            }

            if (sb.Length >= minLength)
                results.Add(sb.ToString());

            return results;
        }

        private static List<string> ExtractWideStrings(byte[] data, int minLength)
        {
            var results = new List<string>();
            var sb = new StringBuilder();

            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                if (c >= 0x20 && c < 0x7F)
                {
                    sb.Append(c);
                }
                else
                {
                    if (sb.Length >= minLength)
                        results.Add(sb.ToString());
                    sb.Clear();
                }
            }

            if (sb.Length >= minLength)
                results.Add(sb.ToString());

            return results;
        }
    }
}
