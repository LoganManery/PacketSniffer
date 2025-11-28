using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Holds traffic data for a single device
    /// </summary>
    public class DeviceTrafficData
    {
        public string IpAddress { get; set; }
        public string MacAddress { get; set; } // Can be populated later via ARP
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public DateTime? LastIdentified { get; set; }
        public int TotalPackets { get; set; }
        public HashSet<int> ObservedPorts { get; set; } = new();
        public Dictionary<int, List<int>> PacketSizesByPort { get; set; } = new();
        public Dictionary<int, List<DateTime>> PacketTimestampsByPort { get; set; } = new();
        public DetectionResult IdentificationResult { get; set; }

        public DeviceTrafficData(string ipAddress)
        {
            IpAddress = ipAddress;
            FirstSeen = DateTime.Now;
            LastSeen = DateTime.Now;
        }
    }
}
