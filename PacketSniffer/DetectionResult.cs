using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class DetectionResult
    {
        public string DeviceType { get; set; }
        public decimal ConfidenceScore { get; set; }
        public List<string> MatchedPatterns { get; set; }
        public string Method { get; set; } // "PORT", "MAC", "PATTERN", "KNOWN"
    }
}
