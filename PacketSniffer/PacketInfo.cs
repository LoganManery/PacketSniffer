using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Represents information about a captured network packet
    /// </summary>
    public class PacketInfo
    {
        public string Protocol { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string TransportInfo { get; set; }
        public DateTime Timestamp { get; set; }
        public int Length { get; set; }

        public PacketInfo()
        {
            Timestamp = DateTime.Now;
        }

        public override string ToString()
        {
            return $"[{Timestamp:HH:mm:ss.fff}] {Protocol} {SourceIP}:{SourcePort} -> {DestinationIP}:{DestinationPort}";
        }
    }
}
