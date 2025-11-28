using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class TrafficPattern
    {
        public int PatternId { get; set; }
        public int SignatureId { get; set; }
        public string PatternType { get; set; } // PORT, PACKET_SIZE, FREQUENCY, PROTOCOL
        public string PatternValue { get; set; }
        public decimal Weight { get; set; }
        public string Description { get; set; }
    }
}
