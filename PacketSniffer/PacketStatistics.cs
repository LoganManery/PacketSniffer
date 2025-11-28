using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Tracks packet capture statistics
    /// </summary>
    public class PacketStatistics
    {
        private Dictionary<string, int> _protocolCounts = new Dictionary<string, int>();
        private Dictionary<string, int> _ipCounts = new Dictionary<string, int>();
        private int _totalPackets = 0;
        private DateTime _captureStartTime;

        public PacketStatistics()
        {
            _captureStartTime = DateTime.Now;
        }

        /// <summary>
        /// Records a captured packet in the statistics
        /// </summary>
        /// <param name="packet">Packet to record</param>
        public void RecordPacket(PacketInfo packet)
        {
            if (packet == null)
                return;

            _totalPackets++;

            // Count by protocol
            if (!_protocolCounts.ContainsKey(packet.Protocol))
                _protocolCounts[packet.Protocol] = 0;
            _protocolCounts[packet.Protocol]++;

            // Count by source IP
            if (!_ipCounts.ContainsKey(packet.SourceIP))
                _ipCounts[packet.SourceIP] = 0;
            _ipCounts[packet.SourceIP]++;

            // Count by destination IP
            if (!_ipCounts.ContainsKey(packet.DestinationIP))
                _ipCounts[packet.DestinationIP] = 0;
            _ipCounts[packet.DestinationIP]++;
        }

        /// <summary>
        /// Displays capture statistics to console
        /// </summary>
        public void DisplayStatistics()
        {
            TimeSpan duration = DateTime.Now - _captureStartTime;

            Console.WriteLine("\n\n=== Packet Capture Statistics ===");
            Console.WriteLine($"Capture Duration: {duration.TotalSeconds:F2} seconds");
            Console.WriteLine($"Total Packets Captured: {_totalPackets:N0}");

            if (_totalPackets > 0)
            {
                Console.WriteLine($"Average Packets/Second: {_totalPackets / duration.TotalSeconds:F2}");
            }

            // Display protocol distribution
            if (_protocolCounts.Count > 0)
            {
                Console.WriteLine("\n--- Protocol Distribution ---");
                foreach (var kvp in _protocolCounts.OrderByDescending(x => x.Value))
                {
                    double percentage = (double)kvp.Value / _totalPackets * 100;
                    string bar = new string('█', (int)(percentage / 2)); // Simple bar chart
                    Console.WriteLine($"  {kvp.Key,-10} {kvp.Value,8:N0} packets ({percentage,5:F1}%) {bar}");
                }
            }

            // Display top communicating IPs
            if (_ipCounts.Count > 0)
            {
                Console.WriteLine("\n--- Top 10 Most Active IPs ---");
                int count = 0;
                foreach (var kvp in _ipCounts.OrderByDescending(x => x.Value).Take(10))
                {
                    count++;
                    double percentage = (double)kvp.Value / (_totalPackets * 2) * 100; // *2 because each packet has src+dst
                    Console.WriteLine($"  {count,2}. {kvp.Key,-15} {kvp.Value,8:N0} packets ({percentage,5:F1}%)");
                }
            }
        }

        /// <summary>
        /// Gets the total number of packets captured
        /// </summary>
        public int TotalPackets => _totalPackets;

        /// <summary>
        /// Gets protocol distribution
        /// </summary>
        public IReadOnlyDictionary<string, int> ProtocolCounts => _protocolCounts;

        /// <summary>
        /// Gets IP address activity counts
        /// </summary>
        public IReadOnlyDictionary<string, int> IPCounts => _ipCounts;
    }
}
