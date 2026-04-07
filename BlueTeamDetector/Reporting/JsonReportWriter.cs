using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using BlueTeamDetector.Analysis;

namespace BlueTeamDetector.Reporting
{
    internal static class JsonReportWriter
    {
        public static void Write(IReadOnlyCollection<DetectionFinding> findings, string outputPath)
        {
            var json = JsonSerializer.Serialize(findings, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(outputPath, json);
        }
    }
}
