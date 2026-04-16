using System;
using System.Collections.Generic;
using BlueTeamDetector.Analysis;
using BlueTeamDetector.Reporting;

namespace BlueTeamDetector
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                var options = CliOptions.Parse(args);
                var scanner = new RepoScanner();
                var analyzer = new EventLogAnalyzer();
                var findings = new List<DetectionFinding>();

                var binaryAnalyzer = new BinaryAnalyzer();

                switch (options.Mode)
                {
                    case ExecutionMode.ScanRepo:
                        findings.AddRange(scanner.Scan(options.TargetPath));
                        break;
                    case ExecutionMode.ScanEvents:
                        findings.AddRange(analyzer.Scan(options.TargetPath));
                        break;
                    case ExecutionMode.ScanBinary:
                        findings.AddRange(binaryAnalyzer.Scan(options.TargetPath));
                        break;
                    case ExecutionMode.Demo:
                        findings.AddRange(scanner.Scan(options.TargetPath));
                        findings.AddRange(analyzer.Scan(options.EventPath));
                        break;
                    default:
                        PrintUsage();
                        return 1;
                }

                findings.Sort(DetectionFindingComparer.BySeverityThenId);
                ConsoleReportWriter.Write(findings, options);

                if (!string.IsNullOrWhiteSpace(options.JsonOutputPath))
                {
                    JsonReportWriter.Write(findings, options.JsonOutputPath);
                    Console.WriteLine();
                    Console.WriteLine($"[+] JSON report written to {options.JsonOutputPath}");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Detector failed");
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("BlueTeamDetector");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  BlueTeamDetector scan-repo <path> [--json <output.json>]");
            Console.WriteLine("  BlueTeamDetector scan-events <sample-events.json> [--json <output.json>]");
            Console.WriteLine("  BlueTeamDetector scan-binary <file.exe> [--json <output.json>]");
            Console.WriteLine("  BlueTeamDetector demo [repoPath] [eventsPath] [--json <output.json>]"  );
        }
    }
}
