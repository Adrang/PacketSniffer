using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    class NetSniffer
    {

        public void StartIPv4Sniffer()
        {
            Console.WriteLine("Hostname: {0}", Dns.GetHostName());

            var IPv4InterAddresses = Dns.GetHostEntry(Dns.GetHostName()).AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork).AsEnumerable();
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName()).AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork).AsEnumerable();

            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 10000);
                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                var endptAddr = endPoint.Address.ToString();
                Console.WriteLine(endptAddr);
                Task.Run(() =>
                {
                    SniffIPv4(IPAddress.Parse(endptAddr));
                });
            }

            Console.WriteLine(new String('-', Console.WindowWidth));

            foreach (IPAddress eachIPv4Addr in IPv4Addresses)
            {
                Console.WriteLine("Starting IPv4 sniffer: {0}", eachIPv4Addr.ToString());
                Task.Run(() =>
                {
                    SniffIPv4(eachIPv4Addr);
                });
            }
        }

        public static void SniffIPv4(IPAddress ip)
        {
            int buffSize = 65535;
            Socket sck = new Socket(ip.AddressFamily, SocketType.Raw, ProtocolType.IP);
            //Socket sck = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            sck.Bind(new IPEndPoint(ip, 0));
            sck.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            sck.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, null);

            byte[] buffer = new byte[buffSize];
            void OnReceive(IAsyncResult ar)
            {
                NetPacket NPacket = new NetPacket(buffer);
                Console.WriteLine(NPacket.ToString());
                buffer = new byte[buffSize];
                sck.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            }

            sck.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }
    }
}
