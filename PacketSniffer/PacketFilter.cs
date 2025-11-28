using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Filters packets based on protocol, IP addresses, and ports
    /// </summary>
    public class PacketFilter
    {
        public string Protocol { get; set; }
        public string SourceIP { get; set; }
        public string DestIP { get; set; }
        public int? Port { get; set; }

        /// <summary>
        /// Checks if any filters are active
        /// </summary>
        public bool HasFilters()
        {
            return !string.IsNullOrEmpty(Protocol) ||
                   !string.IsNullOrEmpty(SourceIP) ||
                   !string.IsNullOrEmpty(DestIP) ||
                   Port.HasValue;
        }

        /// <summary>
        /// Checks if a packet matches the filter criteria
        /// </summary>
        /// <param name="packet">Packet to check</param>
        /// <returns>True if packet matches all filter criteria</returns>
        public bool Matches(PacketInfo packet)
        {
            if (packet == null)
                return false;

            // Check protocol filter
            if (!string.IsNullOrEmpty(Protocol) &&
                !packet.Protocol.Equals(Protocol, StringComparison.OrdinalIgnoreCase))
                return false;

            // Check source IP filter
            if (!string.IsNullOrEmpty(SourceIP) && packet.SourceIP != SourceIP)
                return false;

            // Check destination IP filter
            if (!string.IsNullOrEmpty(DestIP) && packet.DestinationIP != DestIP)
                return false;

            // Check port filter (matches either source or destination port)
            if (Port.HasValue &&
                packet.SourcePort != Port.Value &&
                packet.DestinationPort != Port.Value)
                return false;

            return true;
        }
    }
}
