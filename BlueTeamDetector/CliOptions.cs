using System;
using System.IO;

namespace BlueTeamDetector
{
    internal enum ExecutionMode
    {
        Unknown,
        ScanRepo,
        ScanEvents,
        ScanBinary,
        Demo
    }

    internal sealed class CliOptions
    {
        public ExecutionMode Mode { get; private set; }
        public string TargetPath { get; private set; } = string.Empty;
        public string EventPath { get; private set; } = string.Empty;
        public string JsonOutputPath { get; private set; } = string.Empty;

        public static CliOptions Parse(string[] args)
        {
            if (args.Length == 0)
            {
                return new CliOptions { Mode = ExecutionMode.Unknown };
            }

            var mode = ParseMode(args[0]);
            var options = new CliOptions { Mode = mode };

            switch (mode)
            {
                case ExecutionMode.ScanRepo:
                    options.TargetPath = args.Length > 1 ? Normalize(args[1]) : Normalize("..");
                    break;
                case ExecutionMode.ScanEvents:
                    options.TargetPath = args.Length > 1
                        ? Normalize(args[1])
                        : Normalize(Path.Combine("samples", "sample-sysmon-events.json"));
                    break;
                case ExecutionMode.ScanBinary:
                    if (args.Length < 2)
                        throw new ArgumentException("scan-binary requires a file path.");
                    options.TargetPath = Normalize(args[1]);
                    break;
                case ExecutionMode.Demo:
                    options.TargetPath = args.Length > 1 ? Normalize(args[1]) : Normalize("..");
                    options.EventPath = args.Length > 2
                        ? Normalize(args[2])
                        : Normalize(Path.Combine("samples", "sample-sysmon-events.json"));
                    break;
                default:
                    return options;
            }

            for (var i = 1; i < args.Length; i++)
            {
                if (!string.Equals(args[i], "--json", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException("Missing value for --json.");
                }

                options.JsonOutputPath = Normalize(args[i + 1]);
                i++;
            }

            return options;
        }

        private static ExecutionMode ParseMode(string rawMode)
        {
            if (string.Equals(rawMode, "scan-repo", StringComparison.OrdinalIgnoreCase))
            {
                return ExecutionMode.ScanRepo;
            }

            if (string.Equals(rawMode, "scan-events", StringComparison.OrdinalIgnoreCase))
            {
                return ExecutionMode.ScanEvents;
            }

            if (string.Equals(rawMode, "scan-binary", StringComparison.OrdinalIgnoreCase))
            {
                return ExecutionMode.ScanBinary;
            }

            if (string.Equals(rawMode, "demo", StringComparison.OrdinalIgnoreCase))
            {
                return ExecutionMode.Demo;
            }

            return ExecutionMode.Unknown;
        }

        private static string Normalize(string path)
        {
            return Path.GetFullPath(path);
        }
    }
}
