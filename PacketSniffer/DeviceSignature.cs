using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class DeviceSignature
    {
        public int SignatureId { get; set; }
        public string DeviceType { get; set; }
        public string Manufacturer { get; set; }
        public decimal ConfidenceThreshold { get; set; }
        public string Description { get; set; }
        public List<TrafficPattern> Patterns { get; set; }
    }
}
