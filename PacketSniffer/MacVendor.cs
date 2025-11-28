using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class MacVendor
    {
        public int VendorId { get; set; }
        public string MacPrefix { get; set; } // "00:1A:11"
        public string VendorName { get; set; }
        public string VendorDetails { get; set; }
    }
}
