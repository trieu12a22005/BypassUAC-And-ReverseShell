using System;
using System.Collections.Generic;

namespace BlueTeamDetector.Analysis
{
    internal enum Severity
    {
        Informational = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    internal sealed class EvidenceItem
    {
        public string Source { get; set; } = string.Empty;
        public int? LineNumber { get; set; }
        public string Snippet { get; set; } = string.Empty;
    }

    internal sealed class DetectionFinding
    {
        public string RuleId { get; set; } = string.Empty;
        public Severity Severity { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Technique { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public int Score { get; set; }
        public List<EvidenceItem> Evidence { get; } = new List<EvidenceItem>();
        public Dictionary<string, string> Metadata { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    internal static class DetectionFindingComparer
    {
        public static IComparer<DetectionFinding> BySeverityThenId { get; } = new SeverityThenIdComparer();

        private sealed class SeverityThenIdComparer : IComparer<DetectionFinding>
        {
            public int Compare(DetectionFinding? x, DetectionFinding? y)
            {
                if (ReferenceEquals(x, y))
                {
                    return 0;
                }

                if (x is null)
                {
                    return 1;
                }

                if (y is null)
                {
                    return -1;
                }

                var severityCompare = y.Severity.CompareTo(x.Severity);
                return severityCompare != 0
                    ? severityCompare
                    : string.Compare(x.RuleId, y.RuleId, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
}
