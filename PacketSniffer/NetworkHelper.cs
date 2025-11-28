using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    /// <summary>
    /// Provides network-related helper functions
    /// </summary>
    public static class NetworkHelper
    {
        /// <summary>
        /// Gets the local IPv4 address of the machine
        /// </summary>
        /// <returns>Local IP address as string, or empty string if not found</returns>
        public static string GetLocalIPAddress()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    // Return the first IPv4 address found
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting local IP address: {ex.Message}");
            }
            return string.Empty;
        }

        /// <summary>
        /// Validates if a string is a valid IPv4 address
        /// </summary>
        /// <param name="ipAddress">IP address string to validate</param>
        /// <returns>True if valid IPv4 address</returns>
        public static bool IsValidIPv4(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            string[] parts = ipAddress.Split('.');
            if (parts.Length != 4)
                return false;

            foreach (string part in parts)
            {
                if (!byte.TryParse(part, out byte value))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Checks if a port number is valid
        /// </summary>
        /// <param name="port">Port number to validate</param>
        /// <returns>True if port is in valid range (1-65535)</returns>
        public static bool IsValidPort(int port)
        {
            return port > 0 && port <= 65535;
        }
    }
}
