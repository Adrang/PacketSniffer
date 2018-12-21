using System;

namespace PacketSniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting network sniffer...");
            NetSniffer sniffer = new NetSniffer();
            sniffer.StartIPv4Sniffer();

            Console.ReadKey();
        }
    }
}
