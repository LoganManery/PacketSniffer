using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Tracks devices on the network and their traffic patterns
    /// </summary>
    public class DeviceTracker
    {
        private readonly Dictionary<string, DeviceTrafficData> _devices = new();
        private readonly DeviceIdentificationService _identificationService;
        private readonly object _lock = new();
        private DateTime _lastIdentificationRun = DateTime.MinValue;
        private const int IDENTIFICATION_INTERVAL_SECONDS = 30; // Run identification every 30 seconds

        public DeviceTracker(DeviceIdentificationService identificationService)
        {
            _identificationService = identificationService;
        }

        /// <summary>
        /// Records a packet for device tracking
        /// </summary>
        public void RecordPacket(PacketInfo packet)
        {
            if (packet == null) return;

            lock (_lock)
            {
                // Track source device
                TrackDevice(packet.SourceIP, packet);

                // Track destination device (if it's on local network)
                if (IsLocalIP(packet.DestinationIP))
                {
                    TrackDevice(packet.DestinationIP, packet);
                }
            }
        }

        private void TrackDevice(string ipAddress, PacketInfo packet)
        {
            if (!_devices.ContainsKey(ipAddress))
            {
                _devices[ipAddress] = new DeviceTrafficData(ipAddress);
            }

            var device = _devices[ipAddress];
            device.LastSeen = DateTime.Now;
            device.TotalPackets++;

            // Track ports
            if (packet.SourceIP == ipAddress && packet.SourcePort > 0)
            {
                device.ObservedPorts.Add(packet.SourcePort);
            }
            if (packet.DestinationIP == ipAddress && packet.DestinationPort > 0)
            {
                device.ObservedPorts.Add(packet.DestinationPort);
            }

            // Track packet sizes by port
            int port = packet.SourceIP == ipAddress ? packet.SourcePort : packet.DestinationPort;
            if (port > 0)
            {
                if (!device.PacketSizesByPort.ContainsKey(port))
                {
                    device.PacketSizesByPort[port] = new List<int>();
                }
                device.PacketSizesByPort[port].Add(packet.Length);

                // Track packet timing for frequency calculation
                if (!device.PacketTimestampsByPort.ContainsKey(port))
                {
                    device.PacketTimestampsByPort[port] = new List<DateTime>();
                }
                device.PacketTimestampsByPort[port].Add(packet.Timestamp);
            }
        }

        /// <summary>
        /// Runs device identification for all tracked devices
        /// </summary>
        public async Task RunIdentificationAsync()
        {
            // Only run if enough time has passed
            if ((DateTime.Now - _lastIdentificationRun).TotalSeconds < IDENTIFICATION_INTERVAL_SECONDS)
            {
                return;
            }

            _lastIdentificationRun = DateTime.Now;

            List<DeviceTrafficData> devicesToIdentify;
            lock (_lock)
            {
                devicesToIdentify = _devices.Values
                    .Where(d => d.TotalPackets >= 10) // Only identify devices with enough traffic
                    .ToList();
            }

            foreach (var device in devicesToIdentify)
            {
                try
                {
                    var observedPorts = device.ObservedPorts.ToList();
                    var packetSizes = CalculateAveragePacketSizes(device);
                    var frequencies = CalculatePacketFrequencies(device);

                    var result = await _identificationService.IdentifyDeviceAsync(
                        device.IpAddress,
                        device.MacAddress, // Will be null for now, could add ARP lookup later
                        observedPorts,
                        packetSizes,
                        frequencies);

                    device.IdentificationResult = result;
                    device.LastIdentified = DateTime.Now;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error identifying device {device.IpAddress}: {ex.Message}");
                }
            }
        }

        private Dictionary<int, int> CalculateAveragePacketSizes(DeviceTrafficData device)
        {
            var result = new Dictionary<int, int>();
            foreach (var kvp in device.PacketSizesByPort)
            {
                if (kvp.Value.Count > 0)
                {
                    result[kvp.Key] = (int)kvp.Value.Average();
                }
            }
            return result;
        }

        private Dictionary<int, int> CalculatePacketFrequencies(DeviceTrafficData device)
        {
            var result = new Dictionary<int, int>();
            foreach (var kvp in device.PacketTimestampsByPort)
            {
                if (kvp.Value.Count >= 2)
                {
                    var timestamps = kvp.Value.OrderBy(t => t).ToList();
                    var intervals = new List<double>();

                    for (int i = 1; i < timestamps.Count; i++)
                    {
                        intervals.Add((timestamps[i] - timestamps[i - 1]).TotalMilliseconds);
                    }

                    if (intervals.Count > 0)
                    {
                        var avgInterval = intervals.Average();
                        // Convert to packets per second, then to interval in ms
                        result[kvp.Key] = (int)avgInterval;
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Gets all tracked devices
        /// </summary>
        public List<DeviceTrafficData> GetTrackedDevices()
        {
            lock (_lock)
            {
                return _devices.Values.OrderByDescending(d => d.TotalPackets).ToList();
            }
        }

        /// <summary>
        /// Displays device identification summary
        /// </summary>
        public void DisplayDeviceSummary()
        {
            var devices = GetTrackedDevices();

            Console.WriteLine("\n\n=== Identified Devices ===");
            Console.WriteLine($"Total Devices Tracked: {devices.Count}\n");

            foreach (var device in devices.Take(20)) // Show top 20
            {
                Console.WriteLine($"IP: {device.IpAddress,-15} Packets: {device.TotalPackets,6}");

                if (device.IdentificationResult != null)
                {
                    var result = device.IdentificationResult;
                    Console.WriteLine($"  Type: {result.DeviceType}");
                    Console.WriteLine($"  Confidence: {result.ConfidenceScore:P1}");
                    Console.WriteLine($"  Method: {result.Method}");

                    if (device.ObservedPorts.Any())
                    {
                        var topPorts = device.ObservedPorts
                            .GroupBy(p => p)
                            .OrderByDescending(g => g.Count())
                            .Take(5)
                            .Select(g => g.Key);
                        Console.WriteLine($"  Top Ports: {string.Join(", ", topPorts)}");
                    }
                }
                else
                {
                    Console.WriteLine("  Type: Not yet identified");
                }

                Console.WriteLine($"  Last Seen: {device.LastSeen:HH:mm:ss}");
                Console.WriteLine();
            }
        }

        public void DisplayDetailedDeviceSummary()
        {
            var devices = GetTrackedDevices();

            Console.WriteLine("\n\n=== Detailed Device Analysis ===");
            Console.WriteLine($"Total Devices Tracked: {devices.Count}\n");

            // Show guide first
            DeviceDiagnostics.DisplayDeviceTypeGuide();

            // Show detailed info for each device
            foreach (var device in devices)
            {
                DeviceDiagnostics.DisplayDetailedDeviceInfo(device);
            }
        }

        private bool IsLocalIP(string ip)
        {
            // Simple check for common private IP ranges
            return ip.StartsWith("10.") ||
                   ip.StartsWith("192.168.") ||
                   ip.StartsWith("172.16.") ||
                   ip.StartsWith("172.17.") ||
                   ip.StartsWith("172.18.") ||
                   ip.StartsWith("172.19.") ||
                   ip.StartsWith("172.20.") ||
                   ip.StartsWith("172.21.") ||
                   ip.StartsWith("172.22.") ||
                   ip.StartsWith("172.23.") ||
                   ip.StartsWith("172.24.") ||
                   ip.StartsWith("172.25.") ||
                   ip.StartsWith("172.26.") ||
                   ip.StartsWith("172.27.") ||
                   ip.StartsWith("172.28.") ||
                   ip.StartsWith("172.29.") ||
                   ip.StartsWith("172.30.") ||
                   ip.StartsWith("172.31.");
        }
    }
}
