using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class Port
    {
        public int PortId { get; set; }
        public int PortNumber { get; set; }
        public string Protocol { get; set; } // TCP, UDP, BOTH
        public string ServiceName { get; set; }
        public string Description { get; set; }
        public bool IsWellKnown { get; set; }
    }
}
