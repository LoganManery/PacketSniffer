using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Parses raw packet bytes into structured PacketInfo objects
    /// </summary>
    public class PacketParser
    {
        /// <summary>
        /// Parses a raw packet buffer into a PacketInfo object
        /// </summary>
        /// <param name="buffer">Raw packet bytes</param>
        /// <param name="length">Length of valid data in buffer</param>
        /// <returns>PacketInfo object or null if packet cannot be parsed</returns>
        public PacketInfo ParsePacket(byte[] buffer, int length)
        {
            try
            {
                // Minimum IP header size is 20 bytes
                if (length < 20)
                    return null;

                // Parse IP header
                byte versionAndHeaderLength = buffer[0];
                int version = (versionAndHeaderLength >> 4) & 0x0F;
                int headerLength = (versionAndHeaderLength & 0x0F) * 4;

                // Only handle IPv4
                if (version != 4)
                    return null;

                // Extract protocol
                byte protocolNumber = buffer[9];
                string protocol = GetProtocolName(protocolNumber);

                // Extract source and destination IP addresses
                string sourceIP = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";
                string destIP = $"{buffer[16]}.{buffer[17]}.{buffer[18]}.{buffer[19]}";

                // Create packet info object
                var packetInfo = new PacketInfo
                {
                    Protocol = protocol,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    Length = length
                };

                // Parse transport layer if present
                if (length > headerLength)
                {
                    if (protocolNumber == 6) // TCP
                    {
                        ParseTCP(buffer, headerLength, packetInfo);
                    }
                    else if (protocolNumber == 17) // UDP
                    {
                        ParseUDP(buffer, headerLength, packetInfo);
                    }
                    else if (protocolNumber == 1) // ICMP
                    {
                        ParseICMP(buffer, headerLength, packetInfo);
                    }
                }

                return packetInfo;
            }
            catch
            {
                // Ignore malformed packets
                return null;
            }
        }

        /// <summary>
        /// Parses TCP header information
        /// </summary>
        private void ParseTCP(byte[] buffer, int offset, PacketInfo packet)
        {
            try
            {
                if (buffer.Length < offset + 20)
                    return;

                // Parse ports (big-endian)
                ushort sourcePort = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
                ushort destPort = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

                packet.SourcePort = sourcePort;
                packet.DestinationPort = destPort;

                // Parse TCP flags
                byte flags = buffer[offset + 13];
                string flagsStr = GetTCPFlags(flags);

                // Parse sequence number
                uint seqNum = (uint)((buffer[offset + 4] << 24) |
                                     (buffer[offset + 5] << 16) |
                                     (buffer[offset + 6] << 8) |
                                     buffer[offset + 7]);

                packet.TransportInfo = $"Port {sourcePort} -> {destPort} [{flagsStr}] Seq={seqNum}";
            }
            catch { }
        }

        /// <summary>
        /// Parses UDP header information
        /// </summary>
        private void ParseUDP(byte[] buffer, int offset, PacketInfo packet)
        {
            try
            {
                if (buffer.Length < offset + 8)
                    return;

                // Parse ports (big-endian)
                ushort sourcePort = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
                ushort destPort = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);

                packet.SourcePort = sourcePort;
                packet.DestinationPort = destPort;

                // Parse length
                ushort udpLength = (ushort)((buffer[offset + 4] << 8) | buffer[offset + 5]);

                packet.TransportInfo = $"Port {sourcePort} -> {destPort} Len={udpLength}";
            }
            catch { }
        }

        /// <summary>
        /// Parses ICMP header information
        /// </summary>
        private void ParseICMP(byte[] buffer, int offset, PacketInfo packet)
        {
            try
            {
                if (buffer.Length < offset + 8)
                    return;

                byte type = buffer[offset];
                byte code = buffer[offset + 1];

                string icmpType = GetICMPType(type);
                packet.TransportInfo = $"Type={type} ({icmpType}) Code={code}";
            }
            catch { }
        }

        /// <summary>
        /// Converts TCP flag byte to readable string
        /// </summary>
        private string GetTCPFlags(byte flags)
        {
            StringBuilder sb = new StringBuilder();
            if ((flags & 0x01) != 0) sb.Append("FIN ");
            if ((flags & 0x02) != 0) sb.Append("SYN ");
            if ((flags & 0x04) != 0) sb.Append("RST ");
            if ((flags & 0x08) != 0) sb.Append("PSH ");
            if ((flags & 0x10) != 0) sb.Append("ACK ");
            if ((flags & 0x20) != 0) sb.Append("URG ");
            return sb.ToString().TrimEnd();
        }

        /// <summary>
        /// Converts protocol number to name
        /// </summary>
        private string GetProtocolName(byte protocol)
        {
            return protocol switch
            {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                2 => "IGMP",
                47 => "GRE",
                50 => "ESP",
                51 => "AH",
                89 => "OSPF",
                _ => $"Proto-{protocol}"
            };
        }

        /// <summary>
        /// Converts ICMP type to readable name
        /// </summary>
        private string GetICMPType(byte type)
        {
            return type switch
            {
                0 => "Echo Reply",
                3 => "Dest Unreachable",
                5 => "Redirect",
                8 => "Echo Request",
                11 => "Time Exceeded",
                _ => "Unknown"
            };
        }
    }
}
