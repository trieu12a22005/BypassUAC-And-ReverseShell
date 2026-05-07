using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace BlueTeamDetector.Analysis
{
    internal sealed class EventLogAnalyzer
    {
        private static readonly string[] AutoElevatedBinaries =
        {
            "computerdefaults.exe",
            "fodhelper.exe",
            "eventvwr.exe",
            "winver.exe"
        };

        public IReadOnlyList<DetectionFinding> Scan(string jsonPath)
        {
            if (!File.Exists(jsonPath))
            {
                throw new FileNotFoundException($"Event file not found: {jsonPath}");
            }

            var json = File.ReadAllText(jsonPath);
            var events = JsonSerializer.Deserialize<List<SysmonLikeEvent>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new List<SysmonLikeEvent>();

            var findings = new List<DetectionFinding>();
            findings.AddRange(DetectAutoElevatedProcessChain(events, jsonPath));
            findings.AddRange(DetectElevatedPayloadLaunch(events, jsonPath));
            findings.AddRange(DetectRegistryHijack(events, jsonPath));
            findings.AddRange(DetectReverseCallback(events, jsonPath));
            findings.AddRange(DetectCorrelatedAttack(events, jsonPath));
            return findings;
        }

        private static IEnumerable<DetectionFinding> DetectAutoElevatedProcessChain(IEnumerable<SysmonLikeEvent> events, string source)
        {
            foreach (var evt in events.Where(e => e.EventId == 1 && AutoElevatedBinaries.Contains(NormalizeName(e.Image))))
            {
                yield return BuildFinding(
                    "EVT-UAC-001",
                    Severity.Medium,
                    "Auto-elevated Windows binary appeared in process chain",
                    "T1548.002",
                    "Event telemetry shows an auto-elevated Windows binary that is frequently abused for UAC bypass or privilege manipulation.",
                    "Review parent image, integrity level, and subsequent child processes to determine whether the launch was expected.",
                    35,
                    source,
                    evt,
                    evt.Image ?? string.Empty);
            }
        }

        private static IEnumerable<DetectionFinding> DetectElevatedPayloadLaunch(IEnumerable<SysmonLikeEvent> events, string source)
        {
            foreach (var evt in events.Where(e => e.EventId == 1 && IsElevated(e.IntegrityLevel) && IsSuspiciousUserPath(e.Image)))
            {
                yield return BuildFinding(
                    "EVT-UAC-002",
                    Severity.High,
                    "Elevated payload launched from non-standard path",
                    "T1548.002",
                    "A high-integrity process was launched from a path that is unusual for trusted administrative software.",
                    "Alert on high-integrity child processes that execute from temp, user-writable, or hardcoded staging directories.",
                    65,
                    source,
                    evt,
                    evt.Image ?? string.Empty,
                    evt.ParentImage ?? string.Empty,
                    evt.IntegrityLevel ?? string.Empty);
            }
        }

        private static IEnumerable<DetectionFinding> DetectRegistryHijack(IEnumerable<SysmonLikeEvent> events, string source)
        {
            foreach (var evt in events.Where(e => e.EventId == 13 && ContainsAny(e.TargetObject, "ms-settings\\shell\\open\\command", "mscfile\\shell\\open\\command")))
            {
                yield return BuildFinding(
                    "EVT-REG-001",
                    Severity.High,
                    "Registry UAC hijack key modified",
                    "T1548.002",
                    "Telemetry shows a registry modification commonly used in fodhelper.exe or eventvwr.exe UAC bypass variants.",
                    "Investigate the process that changed the key and monitor for child processes started immediately afterward.",
                    70,
                    source,
                    evt,
                    evt.TargetObject ?? string.Empty,
                    evt.Details ?? string.Empty);
            }
        }

        private static IEnumerable<DetectionFinding> DetectReverseCallback(IEnumerable<SysmonLikeEvent> events, string source)
        {
            foreach (var evt in events.Where(e => e.EventId == 3 && IsSuspiciousUserPath(e.Image)))
            {
                yield return BuildFinding(
                    "EVT-C2-001",
                    Severity.High,
                    "Suspicious outbound connection from staged payload",
                    "Command and control",
                    "A payload from a suspicious path initiated a network connection, consistent with reverse-shell or callback behavior.",
                    "Correlate with elevation events and block outbound traffic from unexpected administrative payloads.",
                    55,
                    source,
                    evt,
                    evt.Image ?? string.Empty,
                    evt.DestinationIp ?? string.Empty,
                    evt.DestinationPort?.ToString() ?? string.Empty);
            }
        }

        private static IEnumerable<DetectionFinding> DetectCorrelatedAttack(List<SysmonLikeEvent> events, string source)
        {
            var processEvents = events
                .Where(e => e.EventId == 1)
                .OrderBy(e => e.TimestampUtc)
                .ToList();

            var elevatedPayloads = processEvents
                .Where(e => IsElevated(e.IntegrityLevel) && IsSuspiciousUserPath(e.Image))
                .ToList();

            foreach (var payload in elevatedPayloads)
            {
                var auto = processEvents.LastOrDefault(e =>
                    AutoElevatedBinaries.Contains(NormalizeName(e.Image)) &&
                    e.TimestampUtc <= payload.TimestampUtc &&
                    e.TimestampUtc >= payload.TimestampUtc.AddMinutes(-2));

                if (auto == null)
                {
                    continue;
                }

                var network = events.FirstOrDefault(e =>
                    e.EventId == 3 &&
                    PathsMatch(e.Image, payload.Image) &&
                    e.TimestampUtc >= payload.TimestampUtc &&
                    e.TimestampUtc <= payload.TimestampUtc.AddMinutes(2));

                var finding = BuildFinding(
                    "EVT-UAC-003",
                    Severity.Critical,
                    "Correlated UAC bypass and callback chain",
                    "T1548.002 + in-memory execution",
                    "Telemetry forms a high-confidence chain: auto-elevated system binary, elevated payload from a suspicious path, then outbound connectivity from that payload.",
                    "Escalate immediately, isolate the endpoint, and collect process tree plus memory telemetry for the elevated payload.",
                    95,
                    source,
                    auto,
                    auto.Image ?? string.Empty,
                    payload.Image ?? string.Empty,
                    payload.ParentImage ?? string.Empty);

                AddEventEvidence(finding, source, payload, payload.Image ?? string.Empty, payload.IntegrityLevel ?? string.Empty);
                if (network != null)
                {
                    AddEventEvidence(finding, source, network, network.DestinationIp ?? string.Empty, network.DestinationPort?.ToString() ?? string.Empty);
                }

                yield return finding;
            }
        }

        private static DetectionFinding BuildFinding(
            string ruleId,
            Severity severity,
            string title,
            string technique,
            string description,
            string recommendation,
            int score,
            string source,
            SysmonLikeEvent evt,
            params string[] snippets)
        {
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

            AddEventEvidence(finding, source, evt, snippets);
            return finding;
        }

        private static void AddEventEvidence(DetectionFinding finding, string source, SysmonLikeEvent evt, params string[] snippets)
        {
            var summary = string.Join(" | ", snippets.Where(value => !string.IsNullOrWhiteSpace(value)));
            finding.Evidence.Add(new EvidenceItem
            {
                Source = source,
                Snippet = $"EventId={evt.EventId}; TimestampUtc={evt.TimestampUtc:O}; {summary}"
            });
        }

        private static bool IsElevated(string? integrityLevel)
        {
            return string.Equals(integrityLevel, "High", StringComparison.OrdinalIgnoreCase)
                || string.Equals(integrityLevel, "System", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSuspiciousUserPath(string? image)
        {
            if (string.IsNullOrWhiteSpace(image))
            {
                return false;
            }

            var normalized = image.Replace('/', '\\');
            return normalized.IndexOf("\\update\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\users\\", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool ContainsAny(string? value, params string[] markers)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return markers.Any(marker => value.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static string NormalizeName(string? path)
        {
            return Path.GetFileName(path ?? string.Empty).ToLowerInvariant();
        }

        private static bool PathsMatch(string? left, string? right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal sealed class SysmonLikeEvent
    {
        public int EventId { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string? Image { get; set; }
        public string? ParentImage { get; set; }
        public string? IntegrityLevel { get; set; }
        public string? CommandLine { get; set; }
        public string? TargetObject { get; set; }
        public string? Details { get; set; }
        public string? DestinationIp { get; set; }
        public int? DestinationPort { get; set; }
    }
}
