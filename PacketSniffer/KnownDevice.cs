using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class KnownDevice
    {
        public int DeviceId { get; set; }
        public string IpAddress { get; set; }
        public string MacAddress { get; set; }
        public string DeviceType { get; set; }
        public string FriendlyName { get; set; }
        public DateTime LastSeen { get; set; }
        public int? SignatureId { get; set; }
    }
}
