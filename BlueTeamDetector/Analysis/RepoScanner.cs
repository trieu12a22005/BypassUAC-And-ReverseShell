using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BlueTeamDetector.Analysis
{
    internal sealed class RepoScanner
    {
        private static readonly string[] IncludedExtensions =
        {
            ".cs", ".c", ".h", ".cpp", ".py"
        };

        public IReadOnlyList<DetectionFinding> Scan(string rootPath)
        {
            if (!Directory.Exists(rootPath))
            {
                throw new DirectoryNotFoundException($"Repository path not found: {rootPath}");
            }

            var files = Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories)
                .Where(path => IncludedExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase))
                .Where(path => !IsExcludedPath(path))
                .ToList();

            var findings = new List<DetectionFinding>();

            AddIfFound(findings, files, new[]
            {
                "APPINFO_RPC",
                "RAiLaunchAdminProcess",
                "ComputerDefaults.exe",
                "winver.exe"
            },
            "SRC-UAC-001",
            Severity.High,
            "AppInfo-style UAC bypass indicators in source",
            "T1548.002",
            "Source contains a suspicious combination of AppInfo RPC abuse markers and auto-elevated Windows binaries.",
            "Monitor process creation chains that involve auto-elevated Windows binaries and validate parent-child ancestry for unexpected payload launches.",
            70);

            AddIfFound(findings, files, new[]
            {
                "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                "CreateProcessW",
                "C:\\\\update\\\\ConsoleApp1.exe"
            },
            "SRC-UAC-002",
            Severity.High,
            "Elevated payload spawn from unusual path",
            "T1548.002",
            "Source suggests parent-process spoofing or inherited elevated context used to start a payload from a non-standard path.",
            "Alert when high-integrity child processes launch from user-writable or uncommon directories outside Windows and Program Files.",
            65);

            AddIfFound(findings, files, new[]
            {
                "VirtualAlloc",
                "CreateThread",
                "Marshal.Copy"
            },
            "SRC-MEM-001",
            Severity.Critical,
            "In-memory payload execution pattern",
            "In-memory execution",
            "Source contains a classic shellcode runner sequence: executable allocation, memory copy, and thread creation.",
            "Hunt for memory allocations with execute permissions combined with thread creation and immediate network activity.",
            90);

            AddIfFound(findings, files, new[]
            {
                "VirtualAlloc",
                "RWX"
            },
            "SRC-MEM-002",
            Severity.High,
            "Executable RWX memory allocation indicators",
            "In-memory execution",
            "Source references executable writable memory, which is a strong indicator for shellcode runners and packers.",
            "Use EDR or ETW telemetry to flag RWX allocations made by unsigned or newly launched processes.",
            60);

            AddIfFound(findings, files, new[]
            {
                "XorKey",
                "EncryptedShellcode"
            },
            "SRC-OBF-001",
            Severity.Medium,
            "XOR-obfuscated shellcode markers",
            "T1027",
            "Source includes XOR key material and an encrypted shellcode blob, indicating payload obfuscation before in-memory execution.",
            "Triangulate with runtime telemetry before escalating to high-confidence malware classification.",
            45);

            AddIfFound(findings, files, new[]
            {
                "shell_reverse_tcp",
                "4444"
            },
            "SRC-C2-001",
            Severity.Medium,
            "Reverse-shell operator IOC in project artifacts",
            "Command and control",
            "Source or documentation references reverse-shell tooling and listener setup consistent with callback payloads.",
            "Correlate network events with elevated process launches to reduce false positives from lab notes or training material.",
            40);

            return findings;
        }

        private static void AddIfFound(
            ICollection<DetectionFinding> findings,
            IReadOnlyList<string> files,
            IReadOnlyList<string> requiredMarkers,
            string ruleId,
            Severity severity,
            string title,
            string technique,
            string description,
            string recommendation,
            int score)
        {
            foreach (var file in files)
            {
                var text = File.ReadAllText(file);
                if (!requiredMarkers.All(marker => text.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    continue;
                }

                var finding = new DetectionFinding
                {
                    RuleId = ruleId,
                    Severity = severity,
                    Title = title,
                    Technique = technique,
                    Description = description,
                    Recommendation = recommendation,
                    Score = score
                };

                foreach (var marker in requiredMarkers)
                {
                    var evidence = BuildEvidence(file, text, marker);
                    if (evidence != null)
                    {
                        finding.Evidence.Add(evidence);
                    }
                }

                findings.Add(finding);
            }
        }

        private static EvidenceItem? BuildEvidence(string file, string text, string marker)
        {
            var normalized = text.Replace("\r\n", "\n");
            var lines = normalized.Split('\n');
            for (var index = 0; index < lines.Length; index++)
            {
                if (lines[index].IndexOf(marker, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                return new EvidenceItem
                {
                    Source = file,
                    LineNumber = index + 1,
                    Snippet = lines[index].Trim()
                };
            }

            return null;
        }

        private static bool IsExcludedPath(string path)
        {
            var normalized = path.Replace('/', '\\');
            return normalized.IndexOf("\\.git\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\.vs\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\bin\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\obj\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\BlueTeamDetector\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
