using Npgsql;
using Dapper;
using System;
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
                    (1900, 'UDP', 'SSDP', 'Simple Service Discovery Protocol', true),
                    (3389, 'TCP', 'RDP', 'Remote Desktop Protocol', true),
                    (22, 'TCP', 'SSH', 'Secure Shell', true),
                    (53, 'UDP', 'DNS', 'Domain Name System', true),
                    (21, 'TCP', 'FTP', 'File Transfer Protocol', true),
                    (25, 'TCP', 'SMTP', 'Simple Mail Transfer Protocol', true)
                ON CONFLICT (port_number, protocol) DO NOTHING");

            // Seed Chromecast signature
            var chromecastId = await conn.QuerySingleOrDefaultAsync<int?>(@"
                INSERT INTO device_signatures (device_type, manufacturer, confidence_threshold, description)
                VALUES ('Chromecast', 'Google', 0.70, 'Google Chromecast streaming device')
                ON CONFLICT (device_type) DO UPDATE SET device_type = EXCLUDED.device_type
                RETURNING signature_id");

            if (chromecastId == null)
            {
                chromecastId = await conn.QuerySingleAsync<int>(
                    "SELECT signature_id FROM device_signatures WHERE device_type = 'Chromecast'");
            }

            // Clear existing patterns for this signature
            await conn.ExecuteAsync("DELETE FROM traffic_patterns WHERE signature_id = @id",
                new { id = chromecastId });

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
                    ('B4:F6:1C', 'Google', 'Google Nest devices'),
                    ('D0:76:E7', 'Google', 'Google devices'),
                    ('F4:F5:D8', 'Google', 'Google Home devices')
                ON CONFLICT (mac_prefix) DO NOTHING");

            Console.WriteLine("✓ Database seeded with initial data");
        }
    }
}
