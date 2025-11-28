using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace PacketSniffer
{
    /// <summary>
    /// Handles loading configuration from multiple sources
    /// </summary>
    public static class ConfigurationHelper
    {
        private static IConfiguration? _configuration;

        /// <summary>
        /// Gets the configuration instance
        /// </summary>
        public static IConfiguration Configuration
        {
            get
            {
                if (_configuration == null)
                {
                    LoadConfiguration();
                }
                return _configuration!;
            }
        }

        /// <summary>
        /// Loads configuration from appsettings.json and environment variables
        /// </summary>
        private static void LoadConfiguration()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables("PACKETSNIFFER_"); // Prefix for environment variables

            _configuration = builder.Build();
        }

        /// <summary>
        /// Gets the database connection string
        /// </summary>
        public static string GetConnectionString()
        {
            // Try to get from configuration file first
            var connectionString = Configuration.GetConnectionString("PacketSnifferDb");

            // If not in config file, try environment variable
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = Environment.GetEnvironmentVariable("PACKETSNIFFER_CONNECTION_STRING");
            }

            // If still not found, build from individual environment variables
            if (string.IsNullOrEmpty(connectionString))
            {
                var host = Environment.GetEnvironmentVariable("PACKETSNIFFER_DB_HOST") ?? "localhost";
                var database = Environment.GetEnvironmentVariable("PACKETSNIFFER_DB_NAME") ?? "packet_sniffer";
                var username = Environment.GetEnvironmentVariable("PACKETSNIFFER_DB_USER") ?? "postgres";
                var password = Environment.GetEnvironmentVariable("PACKETSNIFFER_DB_PASSWORD");

                if (!string.IsNullOrEmpty(password))
                {
                    connectionString = $"Host={host};Database={database};Username={username};Password={password}";
                }
            }

            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException(
                    "Database connection string not found. Please configure it using one of these methods:\n" +
                    "1. Create appsettings.json with ConnectionStrings:PacketSnifferDb\n" +
                    "2. Set environment variable: PACKETSNIFFER_CONNECTION_STRING\n" +
                    "3. Set individual environment variables: PACKETSNIFFER_DB_HOST, PACKETSNIFFER_DB_NAME, PACKETSNIFFER_DB_USER, PACKETSNIFFER_DB_PASSWORD");
            }

            return connectionString;
        }

        /// <summary>
        /// Gets a configuration value with a default
        /// </summary>
        public static T GetValue<T>(string key, T defaultValue)
        {
            return Configuration.GetValue<T>(key, defaultValue);
        }
    }
}
