using System;
using System.Collections.Generic;
using System.Linq;
using BlueTeamDetector.Analysis;

namespace BlueTeamDetector.Reporting
{
    internal static class ConsoleReportWriter
    {
        public static void Write(IReadOnlyCollection<DetectionFinding> findings, CliOptions options)
        {
            Console.WriteLine("BlueTeamDetector Report");
            Console.WriteLine("=======================");
            Console.WriteLine($"Mode: {options.Mode}");
            Console.WriteLine($"Total findings: {findings.Count}");
            Console.WriteLine();

            if (findings.Count == 0)
            {
                Console.WriteLine("No findings.");
                return;
            }

            var grouped = findings
                .GroupBy(f => f.Severity)
                .OrderByDescending(group => group.Key);

            foreach (var group in grouped)
            {
                Console.WriteLine($"{group.Key}: {group.Count()}");
            }

            Console.WriteLine();

            foreach (var finding in findings)
            {
                Console.WriteLine($"[{finding.Severity}] {finding.RuleId} - {finding.Title}");
                Console.WriteLine($"  Technique: {finding.Technique}");
                Console.WriteLine($"  Score: {finding.Score}");
                Console.WriteLine($"  Description: {finding.Description}");
                Console.WriteLine($"  Recommendation: {finding.Recommendation}");

                foreach (var evidence in finding.Evidence.Take(3))
                {
                    var location = evidence.LineNumber.HasValue
                        ? $"{evidence.Source}:{evidence.LineNumber.Value}"
                        : evidence.Source;
                    Console.WriteLine($"  Evidence: {location}");
                    Console.WriteLine($"    {evidence.Snippet}");
                }

                Console.WriteLine();
            }
        }
    }
}
