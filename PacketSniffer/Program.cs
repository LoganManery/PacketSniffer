using PacketSniffer;

Console.WriteLine("Enhanced Packet Sniffer");
Console.WriteLine("======================\n");

// Parse command line arguments
var filter = CommandLineParser.ParseArguments(args);

// Get local IP address
string localIP = NetworkHelper.GetLocalIPAddress();
if (string.IsNullOrEmpty(localIP))
{
    Console.WriteLine("Could not determine local IP address.");
    Console.WriteLine("Please check your network connection.");
    return;
}

Console.WriteLine($"Monitoring on: {localIP}");
DisplayFilterInfo(filter);
Console.WriteLine("\nPress Ctrl+C to stop and see statistics\n");

// Initialize statistics tracker
var statistics = new PacketStatistics();

// Set up Ctrl+C handler for graceful shutdown
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    statistics.DisplayStatistics();
    Environment.Exit(0);
};

// Create and start packet capture
try
{
    var capture = new PacketCapture(localIP);
    var parser = new PacketParser();

    Console.WriteLine("Listening for packets...\n");

    capture.StartCapture((buffer, length) =>
    {
        var packetInfo = parser.ParsePacket(buffer, length);
        if (packetInfo != null && filter.Matches(packetInfo))
        {
            statistics.RecordPacket(packetInfo);
            DisplayPacket(packetInfo);
        }
    });
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
    Console.WriteLine("\nNote: This program requires administrator/root privileges.");
    Console.WriteLine("Windows: Run as Administrator");
    Console.WriteLine("Linux/macOS: Run with sudo");
}

        static void DisplayFilterInfo(PacketFilter filter)
{
    if (filter.HasFilters())
    {
        Console.WriteLine("\nActive Filters:");
        if (!string.IsNullOrEmpty(filter.Protocol))
            Console.WriteLine($"  Protocol: {filter.Protocol}");
        if (!string.IsNullOrEmpty(filter.SourceIP))
            Console.WriteLine($"  Source IP: {filter.SourceIP}");
        if (!string.IsNullOrEmpty(filter.DestIP))
            Console.WriteLine($"  Destination IP: {filter.DestIP}");
        if (filter.Port.HasValue)
            Console.WriteLine($"  Port: {filter.Port}");
    }
}

static void DisplayPacket(PacketInfo packet)
{
    string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
    string info = packet.TransportInfo ?? "";
    Console.WriteLine($"[{timestamp}] {packet.Protocol,-8} {packet.SourceIP,-15} -> {packet.DestinationIP,-15} {info}");
}