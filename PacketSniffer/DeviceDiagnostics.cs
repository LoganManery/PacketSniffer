using System;
using System.Collections.Generic;
using System.Linq;

namespace PacketSniffer
{
    /// <summary>
    /// Provides diagnostic information about tracked devices
    /// </summary>
    public static class DeviceDiagnostics
    {
        public static void DisplayDetailedDeviceInfo(DeviceTrafficData device)
        {
            Console.WriteLine($"\n{'=',-60}");
            Console.WriteLine($"Device: {device.IpAddress}");
            Console.WriteLine($"{'=',-60}");
            Console.WriteLine($"Total Packets: {device.TotalPackets}");
            Console.WriteLine($"First Seen: {device.FirstSeen:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Last Seen: {device.LastSeen:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Active Duration: {(device.LastSeen - device.FirstSeen).TotalSeconds:F1} seconds");

            // Port analysis
            if (device.ObservedPorts.Any())
            {
                Console.WriteLine("\n--- Port Activity ---");
                var portGroups = device.PacketSizesByPort
                    .Select(kvp => new
                    {
                        Port = kvp.Key,
                        PacketCount = kvp.Value.Count,
                        AvgSize = kvp.Value.Average(),
                        MinSize = kvp.Value.Min(),
                        MaxSize = kvp.Value.Max()
                    })
                    .OrderByDescending(p => p.PacketCount)
                    .ToList();

                foreach (var portInfo in portGroups)
                {
                    Console.WriteLine($"  Port {portInfo.Port}:");
                    Console.WriteLine($"    Packets: {portInfo.PacketCount}");
                    Console.WriteLine($"    Avg Size: {portInfo.AvgSize:F0} bytes (min: {portInfo.MinSize}, max: {portInfo.MaxSize})");

                    // Try to identify the service
                    var service = GetWellKnownService(portInfo.Port);
                    if (service != null)
                    {
                        Console.WriteLine($"    Service: {service}");
                    }

                    // Calculate frequency if we have timestamps
                    if (device.PacketTimestampsByPort.ContainsKey(portInfo.Port))
                    {
                        var timestamps = device.PacketTimestampsByPort[portInfo.Port].OrderBy(t => t).ToList();
                        if (timestamps.Count >= 2)
                        {
                            var intervals = new List<double>();
                            for (int i = 1; i < timestamps.Count; i++)
                            {
                                intervals.Add((timestamps[i] - timestamps[i - 1]).TotalMilliseconds);
                            }
                            var avgInterval = intervals.Average();
                            Console.WriteLine($"    Avg Interval: {avgInterval:F0}ms (~{1000 / avgInterval:F1} packets/sec)");
                        }
                    }
                }
            }

            // Device type hints
            Console.WriteLine("\n--- Device Type Hints ---");
            var hints = AnalyzeDeviceType(device);
            foreach (var hint in hints)
            {
                Console.WriteLine($"  • {hint}");
            }

            Console.WriteLine();
        }

        private static List<string> AnalyzeDeviceType(DeviceTrafficData device)
        {
            var hints = new List<string>();
            var ports = device.ObservedPorts.ToList();

            // Check for specific port patterns
            if (ports.Contains(5353))
                hints.Add("Uses mDNS (Multicast DNS) - likely Apple device, smart TV, or IoT device");

            if (ports.Contains(8009))
                hints.Add("Uses port 8009 - likely Google Cast device (Chromecast, Google Home, Smart TV with Cast)");

            if (ports.Contains(1900))
                hints.Add("Uses SSDP (port 1900) - UPnP device (Smart TV, media player, printer, or IoT device)");

            if (ports.Contains(3389))
                hints.Add("Uses RDP (port 3389) - Windows computer with Remote Desktop enabled");

            if (ports.Contains(22))
                hints.Add("Uses SSH (port 22) - Linux/Unix computer or network device");

            if (ports.Contains(445) || ports.Contains(139))
                hints.Add("Uses SMB - Windows computer or NAS device");

            if (ports.Contains(548))
                hints.Add("Uses AFP (port 548) - macOS device or Apple network storage");

            if (ports.Contains(62078) || ports.Contains(7000))
                hints.Add("Uses Apple AirPlay ports - Apple TV, HomePod, or AirPlay-enabled device");

            if (ports.Contains(80) && ports.Contains(443))
                hints.Add("Heavy HTTP/HTTPS traffic - could be computer, phone, or smart device");

            if (ports.Contains(53))
                hints.Add("DNS traffic - likely your router or a computer making DNS queries");

            // Check IP address patterns
            if (device.IpAddress.EndsWith(".1"))
                hints.Add("IP ends in .1 - commonly used for routers/gateways");

            if (device.IpAddress.EndsWith(".255"))
                hints.Add("Broadcast address - not a specific device");

            // Check traffic patterns
            if (device.TotalPackets < 10)
                hints.Add("Low packet count - device may be idle or just powered on");

            // Check packet size patterns
            var avgPacketSize = device.PacketSizesByPort.Values
                .SelectMany(sizes => sizes)
                .DefaultIfEmpty()
                .Average();

            if (avgPacketSize < 100)
                hints.Add($"Small packets (avg {avgPacketSize:F0} bytes) - likely control/signaling traffic");
            else if (avgPacketSize > 1000)
                hints.Add($"Large packets (avg {avgPacketSize:F0} bytes) - likely streaming or file transfer");

            if (hints.Count == 0)
                hints.Add("Not enough distinctive traffic patterns to identify device type");

            return hints;
        }

        private static string GetWellKnownService(int port)
        {
            return port switch
            {
                21 => "FTP (File Transfer Protocol)",
                22 => "SSH (Secure Shell)",
                23 => "Telnet",
                25 => "SMTP (Email)",
                53 => "DNS (Domain Name System)",
                67 => "DHCP Server",
                68 => "DHCP Client",
                80 => "HTTP (Web)",
                110 => "POP3 (Email)",
                143 => "IMAP (Email)",
                161 => "SNMP (Network Management)",
                443 => "HTTPS (Secure Web)",
                445 => "SMB (Windows File Sharing)",
                548 => "AFP (Apple File Sharing)",
                631 => "IPP (Internet Printing)",
                993 => "IMAPS (Secure Email)",
                995 => "POP3S (Secure Email)",
                1900 => "SSDP (UPnP Discovery)",
                3306 => "MySQL Database",
                3389 => "RDP (Remote Desktop)",
                5000 => "UPnP/AirPlay",
                5353 => "mDNS (Multicast DNS/Bonjour)",
                5432 => "PostgreSQL Database",
                7000 => "AirPlay",
                8008 => "HTTP Alt/Google Cast",
                8009 => "Google Cast",
                8080 => "HTTP Proxy/Alt",
                8443 => "HTTPS Alt",
                9000 => "Various (SonarQube, etc.)",
                27017 => "MongoDB Database",
                49152 => "Dynamic/Private port",
                62078 => "Apple iCloud/AirPlay",
                _ => null
            };
        }

        public static void DisplayDeviceTypeGuide()
        {
            Console.WriteLine("\n=== Common Device Type Indicators ===\n");

            Console.WriteLine("Routers/Gateways:");
            Console.WriteLine("  • IP ending in .1");
            Console.WriteLine("  • DHCP (ports 67/68), DNS (port 53)");
            Console.WriteLine("  • Often has highest packet count\n");

            Console.WriteLine("Smart TVs / Streaming Devices:");
            Console.WriteLine("  • mDNS (port 5353)");
            Console.WriteLine("  • SSDP/UPnP (port 1900)");
            Console.WriteLine("  • Chromecast: port 8009");
            Console.WriteLine("  • Apple TV: ports 7000, 62078\n");

            Console.WriteLine("Computers:");
            Console.WriteLine("  • Windows: SMB (445), RDP (3389)");
            Console.WriteLine("  • macOS: AFP (548), mDNS (5353)");
            Console.WriteLine("  • Linux: SSH (22)");
            Console.WriteLine("  • High variety of ports\n");

            Console.WriteLine("Mobile Devices:");
            Console.WriteLine("  • mDNS (port 5353)");
            Console.WriteLine("  • Mostly HTTPS (443) traffic");
            Console.WriteLine("  • Bursty traffic patterns\n");

            Console.WriteLine("IoT Devices:");
            Console.WriteLine("  • mDNS (port 5353)");
            Console.WriteLine("  • SSDP (port 1900)");
            Console.WriteLine("  • Regular heartbeat patterns");
            Console.WriteLine("  • Limited port usage\n");
        }
    }
}
