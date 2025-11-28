using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Npgsql;
using Dapper;

namespace PacketSniffer
{
    public class DeviceIdentificationService
    {
        private readonly string _connectionString;

        public DeviceIdentificationService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public async Task<DetectionResult> IdentifyDeviceAsync(
            string ipAddress,
            string macAddress,
            List<int> observedPorts,
            Dictionary<int, int> packetSizes, // port -> avg packet size
            Dictionary<int, int> packetFrequencies) // port -> packets per second
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            var results = new List<(string deviceType, decimal score, string method)>();

            // 1. Check if this is a known device
            var knownDevice = await CheckKnownDeviceAsync(conn, ipAddress, macAddress);
            if (knownDevice != null)
            {
                results.Add((knownDevice.DeviceType, 1.0m, "KNOWN"));
            }

            // 2. MAC address vendor lookup
            if (!string.IsNullOrEmpty(macAddress))
            {
                var vendor = await LookupMacVendorAsync(conn, macAddress);
                if (vendor != null)
                {
                    results.Add((vendor.VendorName, 0.5m, "MAC"));
                }
            }

            // 3. Port-based identification
            foreach (var port in observedPorts)
            {
                var service = await LookupPortServiceAsync(conn, port);
                if (service != null)
                {
                    results.Add((service.ServiceName, 0.6m, "PORT"));
                }
            }

            // 4. Pattern matching
            var patternMatches = await MatchTrafficPatternsAsync(
                conn, observedPorts, packetSizes, packetFrequencies);
            results.AddRange(patternMatches.Select(m => (m.deviceType, m.score, "PATTERN")));

            // Aggregate results and pick best match
            var bestMatch = results
                .GroupBy(r => r.deviceType)
                .Select(g => new DetectionResult
                {
                    DeviceType = g.Key,
                    ConfidenceScore = g.Max(x => x.score),
                    Method = string.Join(", ", g.Select(x => x.method).Distinct()),
                    MatchedPatterns = g.Select(x => $"{x.method}: {x.deviceType}").ToList()
                })
                .OrderByDescending(r => r.ConfidenceScore)
                .FirstOrDefault();

            return bestMatch ?? new DetectionResult
            {
                DeviceType = "Unknown",
                ConfidenceScore = 0,
                MatchedPatterns = new List<string>()
            };
        }

        private async Task<KnownDevice> CheckKnownDeviceAsync(
            NpgsqlConnection conn, string ip, string mac)
        {
            var query = @"
            SELECT * FROM known_devices 
            WHERE (ip_address = @ip OR mac_address = @mac)
            ORDER BY last_seen DESC LIMIT 1";

            return await conn.QueryFirstOrDefaultAsync<KnownDevice>(
                query, new { ip, mac });
        }

        private async Task<MacVendor> LookupMacVendorAsync(
            NpgsqlConnection conn, string macAddress)
        {
            // Extract first 3 octets: "AA:BB:CC:DD:EE:FF" -> "AA:BB:CC"
            var prefix = string.Join(":", macAddress.Split(':').Take(3));

            var query = "SELECT * FROM mac_vendors WHERE mac_prefix = @prefix";
            return await conn.QueryFirstOrDefaultAsync<MacVendor>(
                query, new { prefix });
        }

        private async Task<Port> LookupPortServiceAsync(
            NpgsqlConnection conn, int portNumber)
        {
            var query = @"
            SELECT * FROM ports 
            WHERE port_number = @portNumber 
            AND is_well_known = true
            LIMIT 1";

            return await conn.QueryFirstOrDefaultAsync<Port>(
                query, new { portNumber });
        }

        private async Task<List<(string deviceType, decimal score)>> MatchTrafficPatternsAsync(
            NpgsqlConnection conn,
            List<int> observedPorts,
            Dictionary<int, int> packetSizes,
            Dictionary<int, int> frequencies)
        {
            var query = @"
            SELECT 
                ds.device_type,
                ds.manufacturer,
                ds.confidence_threshold,
                tp.pattern_type,
                tp.pattern_value,
                tp.weight
            FROM device_signatures ds
            JOIN traffic_patterns tp ON ds.signature_id = tp.signature_id";

            var signatures = await conn.QueryAsync(query);

            var matches = new List<(string deviceType, decimal score)>();

            foreach (var sigGroup in signatures.GroupBy(s => s.device_type))
            {
                decimal totalWeight = 0;
                decimal matchedWeight = 0;

                foreach (var pattern in sigGroup)
                {
                    totalWeight += pattern.weight;

                    bool isMatch = pattern.pattern_type switch
                    {
                        "PORT" => observedPorts.Contains(int.Parse(pattern.pattern_value)),
                        "PACKET_SIZE" => CheckPacketSize(packetSizes, pattern.pattern_value),
                        "FREQUENCY" => CheckFrequency(frequencies, pattern.pattern_value),
                        _ => false
                    };

                    if (isMatch)
                    {
                        matchedWeight += pattern.weight;
                    }
                }

                if (totalWeight > 0)
                {
                    decimal confidence = matchedWeight / totalWeight;
                    var threshold = sigGroup.First().confidence_threshold;

                    if (confidence >= threshold)
                    {
                        matches.Add((sigGroup.Key, confidence));
                    }
                }
            }

            return matches;
        }

        private bool CheckPacketSize(Dictionary<int, int> packetSizes, string patternValue)
        {
            // Pattern format: "PORT:SIZE" e.g., "8009:110"
            var parts = patternValue.Split(':');
            if (parts.Length != 2) return false;

            var port = int.Parse(parts[0]);
            var expectedSize = int.Parse(parts[1]);

            if (packetSizes.TryGetValue(port, out var actualSize))
            {
                // Allow 10% variance
                return Math.Abs(actualSize - expectedSize) <= expectedSize * 0.1;
            }

            return false;
        }

        private bool CheckFrequency(Dictionary<int, int> frequencies, string patternValue)
        {
            // Pattern format: "PORT:FREQ_MS" e.g., "8009:5000" (every 5 seconds)
            var parts = patternValue.Split(':');
            if (parts.Length != 2) return false;

            var port = int.Parse(parts[0]);
            var expectedFreqMs = int.Parse(parts[1]);

            if (frequencies.TryGetValue(port, out var packetsPerSec))
            {
                var actualFreqMs = 1000 / packetsPerSec;
                return Math.Abs(actualFreqMs - expectedFreqMs) <= expectedFreqMs * 0.2;
            }

            return false;
        }
    }
}
