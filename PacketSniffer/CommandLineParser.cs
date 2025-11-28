using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Parses command line arguments and creates filter configuration
    /// </summary>
    public static class CommandLineParser
    {
        /// <summary>
        /// Parses command line arguments into a PacketFilter object
        /// </summary>
        /// <param name="args">Command line arguments</param>
        /// <returns>Configured PacketFilter</returns>
        public static PacketFilter ParseArguments(string[] args)
        {
            var filter = new PacketFilter();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--protocol":
                    case "-p":
                        if (i + 1 < args.Length)
                        {
                            filter.Protocol = args[++i].ToUpper();
                        }
                        else
                        {
                            Console.WriteLine("Warning: --protocol requires a value");
                        }
                        break;

                    case "--source":
                    case "-s":
                        if (i + 1 < args.Length)
                        {
                            string sourceIP = args[++i];
                            if (NetworkHelper.IsValidIPv4(sourceIP))
                            {
                                filter.SourceIP = sourceIP;
                            }
                            else
                            {
                                Console.WriteLine($"Warning: Invalid source IP address: {sourceIP}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Warning: --source requires a value");
                        }
                        break;

                    case "--dest":
                    case "-d":
                        if (i + 1 < args.Length)
                        {
                            string destIP = args[++i];
                            if (NetworkHelper.IsValidIPv4(destIP))
                            {
                                filter.DestIP = destIP;
                            }
                            else
                            {
                                Console.WriteLine($"Warning: Invalid destination IP address: {destIP}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Warning: --dest requires a value");
                        }
                        break;

                    case "--port":
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[++i], out int port))
                            {
                                if (NetworkHelper.IsValidPort(port))
                                {
                                    filter.Port = port;
                                }
                                else
                                {
                                    Console.WriteLine($"Warning: Invalid port number: {port}. Must be 1-65535");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Warning: Invalid port number: {args[i]}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Warning: --port requires a value");
                        }
                        break;

                    case "--help":
                    case "-h":
                        DisplayHelp();
                        Environment.Exit(0);
                        break;

                    default:
                        Console.WriteLine($"Warning: Unknown argument: {args[i]}");
                        Console.WriteLine("Use --help for usage information");
                        break;
                }
            }

            return filter;
        }

        /// <summary>
        /// Displays help information
        /// </summary>
        public static void DisplayHelp()
        {
            Console.WriteLine("Packet Sniffer - Network Traffic Analyzer");
            Console.WriteLine("\nUsage: PacketSniffer [options]");
            Console.WriteLine("\nOptions:");
            Console.WriteLine("  -p, --protocol <TCP|UDP|ICMP>  Filter by protocol");
            Console.WriteLine("  -s, --source <IP>              Filter by source IP address");
            Console.WriteLine("  -d, --dest <IP>                Filter by destination IP address");
            Console.WriteLine("  --port <number>                Filter by port number (1-65535)");
            Console.WriteLine("  -h, --help                     Show this help message");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  PacketSniffer --protocol TCP");
            Console.WriteLine("  PacketSniffer --source 192.168.1.1 --protocol UDP");
            Console.WriteLine("  PacketSniffer --port 443");
            Console.WriteLine("  PacketSniffer --dest 8.8.8.8 --protocol ICMP");
            Console.WriteLine("\nNote: Requires administrator/root privileges to capture packets");
            Console.WriteLine("  Windows: Run as Administrator");
            Console.WriteLine("  Linux/macOS: Run with sudo");
        }
    }
}
