using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class ProtocolSignature
    {
        public int ProtocolId { get; set; }
        public string ProtocolName { get; set; }
        public int? PortNumber { get; set; }
        public byte[] SignatureBytes { get; set; }
        public int SignatureOffset { get; set; }
        public string Description { get; set; }
    }
}
