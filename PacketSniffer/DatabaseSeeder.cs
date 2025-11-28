using Npgsql;
using Dapper;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class DatabaseSeeder
    {
        public static async Task SeedInitialDataAsync(string connectionString)
        {
            await using var conn = new NpgsqlConnection(connectionString);
            await conn.OpenAsync();

            // Seed common ports
            await conn.ExecuteAsync(@"
            INSERT INTO ports (port_number, protocol, service_name, description, is_well_known)
            VALUES 
                (80, 'TCP', 'HTTP', 'Hypertext Transfer Protocol', true),
                (443, 'TCP', 'HTTPS', 'HTTP over TLS/SSL', true),
                (8009, 'TCP', 'Google Cast', 'Chromecast Protocol', true),
                (5353, 'UDP', 'mDNS', 'Multicast DNS', true),
                (1900, 'UDP', 'SSDP', 'Simple Service Discovery Protocol', true)
            ON CONFLICT DO NOTHING");

            // Seed Chromecast signature
            await conn.ExecuteAsync(@"
            INSERT INTO device_signatures (device_type, manufacturer, confidence_threshold, description)
            VALUES ('Chromecast', 'Google', 0.70, 'Google Chromecast streaming device')
            RETURNING signature_id",
                new { });

            var chromecastId = await conn.QuerySingleAsync<int>(
                "SELECT signature_id FROM device_signatures WHERE device_type = 'Chromecast'");

            await conn.ExecuteAsync(@"
            INSERT INTO traffic_patterns (signature_id, pattern_type, pattern_value, weight, description)
            VALUES 
                (@id, 'PORT', '8009', 1.5, 'Uses Google Cast protocol'),
                (@id, 'PORT', '5353', 0.8, 'Advertises via mDNS'),
                (@id, 'PACKET_SIZE', '8009:110', 1.0, 'Regular heartbeat packets ~110 bytes'),
                (@id, 'FREQUENCY', '8009:5000', 1.2, 'Heartbeat every ~5 seconds')",
                new { id = chromecastId });

            // Seed Google MAC prefixes
            await conn.ExecuteAsync(@"
            INSERT INTO mac_vendors (mac_prefix, vendor_name, vendor_details)
            VALUES 
                ('6C:AD:F8', 'Google', 'Google Home/Chromecast devices'),
                ('54:60:09', 'Google', 'Google Home/Chromecast devices'),
                ('B4:F6:1C', 'Google', 'Google Nest devices')
            ON CONFLICT DO NOTHING");
        }
    }
}
