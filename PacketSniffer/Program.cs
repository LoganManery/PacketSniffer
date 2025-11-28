using PacketSniffer;

Console.WriteLine("Enhanced Packet Sniffer with Device Identification");
Console.WriteLine("==================================================\n");

// Load configuration securely
string connectionString;
try
{
    connectionString = ConfigurationHelper.GetConnectionString();
    Console.WriteLine("✓ Database configuration loaded successfully");
}
catch (Exception ex)
{
    Console.WriteLine($"Error loading configuration: {ex.Message}");
    Console.WriteLine("\nSetup Instructions:");
    Console.WriteLine("1. Copy appsettings.example.json to appsettings.json");
    Console.WriteLine("2. Edit appsettings.json and add your database password");
    Console.WriteLine("3. Alternatively, set environment variables (see README.md)");
    return;
}

// Rest of your existing code...
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

// Initialize database (first time only)
try
{
    Console.WriteLine("\nInitializing database...");
    await DatabaseSeeder.SeedInitialDataAsync(connectionString);
    Console.WriteLine("Database initialized successfully!");
}
catch (Exception ex)
{
    Console.WriteLine($"Warning: Database initialization failed: {ex.Message}");
    Console.WriteLine("Device identification will not be available.\n");
}

Console.WriteLine("\nPress Ctrl+C to stop and see statistics\n");

// Initialize components
var statistics = new PacketStatistics();
var identificationService = new DeviceIdentificationService(connectionString);
var deviceTracker = new DeviceTracker(identificationService);

// Get identification interval from config (default 30 seconds)
int identificationIntervalSeconds = ConfigurationHelper.GetValue("Settings:IdentificationIntervalSeconds", 30);
var identificationTimer = new System.Timers.Timer(identificationIntervalSeconds * 1000);
identificationTimer.Elapsed += async (sender, e) =>
{
    try
    {
        await deviceTracker.RunIdentificationAsync();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error during device identification: {ex.Message}");
    }
};
identificationTimer.Start();

// Set up Ctrl+C handler for graceful shutdown
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    identificationTimer.Stop();
    statistics.DisplayStatistics();
    deviceTracker.DisplayDetailedDeviceSummary();
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
            deviceTracker.RecordPacket(packetInfo);
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