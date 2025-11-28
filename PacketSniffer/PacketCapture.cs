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
    /// Handles raw socket creation and packet capture
    /// </summary>
    public class PacketCapture
    {
        private const int SIO_RCVALL = unchecked((int)0x98000001);
        private readonly string _ipAddress;
        private Socket? _socket;

        public PacketCapture(string ipAddress)
        {
            _ipAddress = ipAddress;
        }

        /// <summary>
        /// Starts capturing packets and calls the callback for each received packet
        /// </summary>
        /// <param name="callback">Action to invoke with buffer and length for each packet</param>
        public void StartCapture(Action<byte[], int> callback)
        {
            try
            {
                // Create raw socket
                _socket = new Socket(AddressFamily.InterNetwork,
                    SocketType.Raw,
                    ProtocolType.IP);

                // Bind to local IP address
                _socket.Bind(new IPEndPoint(IPAddress.Parse(_ipAddress), 0));

                // Set socket option to include IP header
                _socket.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.HeaderIncluded,
                    true);

                // Enable promiscuous mode to receive all packets
                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                byte[] byOut = new byte[4];
                _socket.IOControl(SIO_RCVALL, byTrue, byOut);

                // Buffer for receiving packets
                byte[] buffer = new byte[65535];

                // Capture loop
                while (true)
                {
                    int received = _socket.Receive(buffer);
                    callback(buffer, received);
                }
            }
            catch (SocketException ex)
            {
                throw new InvalidOperationException(
                    $"Failed to start packet capture: {ex.Message}. " +
                    "Ensure you have administrator/root privileges.", ex);
            }
        }

        /// <summary>
        /// Stops the packet capture and closes the socket
        /// </summary>
        public void Stop()
        {
            if (_socket != null)
            {
                try
                {
                    _socket.Close();
                    _socket.Dispose();
                }
                catch { }
            }
        }
    }
}
