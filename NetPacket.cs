using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace PacketSniffer
{
    public class NetPacket
    {
        public PacketHeader Header { get; set; }
        public IEnumerable<byte> Data { get; set; }

        public NetPacket(byte[] pack)
        {
            Header = new PacketHeader(pack);
            Data = pack.Skip(36);
        }

        public override string ToString()
        {
            string ToReturn = "";

            ToReturn += Header.ToString();

            return ToReturn;
        }
    }

    public class PacketHeader
    {
        public string Version { get; set; }
        public string IHL { get; set; }

        public string DSCP { get; set; }
        public string ECN { get; set; }

        public string PacketLength { get; set; }
        public string Identification { get; set; }

        public string Flags { get; set; }
        public string FragmentOffset { get; set; }

        public string TimeToLive { get; set; }
        public string Protocol { get; set; }

        public string HeaderChecksum { get; set; }

        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }

        public string SourcePort { get; set; }
        public string DestinationPort { get; set; }

        public PacketHeader(byte[] headerData)
        {
            Version = (headerData[0] >> 4).ToString();
            IHL = (headerData[0] & 0x0F).ToString();

            DSCP = (headerData[1] >> 2).ToString();
            ECN = (headerData[1] & 0x03).ToString();

            PacketLength = BitConverter.ToUInt16(headerData, 2).ToString();
            Identification = BitConverter.ToUInt16(headerData, 4).ToString();

            Flags = (BitConverter.ToUInt16(headerData, 6) >> 6).ToString();
            FragmentOffset = (BitConverter.ToUInt16(headerData, 6) & 0x3FFF).ToString();

            TimeToLive = headerData[8].ToString();
            Protocol = ToProtocolString(headerData[9]);

            HeaderChecksum = BitConverter.ToUInt16(headerData, 10).ToString();

            SourceIP = new IPAddress(BitConverter.ToUInt32(headerData, 12)).ToString();
            DestinationIP = new IPAddress(BitConverter.ToUInt32(headerData, 16)).ToString();

            SourcePort = BitConverter.ToUInt16(headerData, 20).ToString();
            DestinationPort = BitConverter.ToUInt16(headerData, 22).ToString();
        }

        public override string ToString()
        {
            string ToReturn = "";

            //try
            //{
            //    ToReturn += string.Format("Src: {0} -> Dst: {1}\n",
            //                            Dns.GetHostEntry(SourceIP).HostName,
            //                            Dns.GetHostEntry(DestinationIP).HostName);
            //    String[] srcAliases = Dns.GetHostEntry(SourceIP).Aliases;
            //    IPAddress[] srcAdress = Dns.GetHostEntry(SourceIP).AddressList;
            //    for (int index = 0; index < srcAliases.Length; index++)
            //    {
            //        ToReturn += "\t" + srcAliases[index] + "\n";
            //    }
            //    for (int index = 0; index < srcAdress.Length; index++)
            //    {
            //        ToReturn += "\t" + srcAdress[index] + "\n";
            //    }

            //} catch(Exception e)
            //{
            //    Console.WriteLine(e.Message);
            //}

            ToReturn += String.Format("Protocol: {6}, Len: {7}, TTL: {8}, Version: {0}, IHL: {1}, Src: {2}:{3}, Dest: {4}:{5}",
                                        Version, IHL,
                                        SourceIP, SourcePort,
                                        DestinationIP, DestinationPort,
                                        Protocol,
                                        PacketLength,
                                        TimeToLive);

            return ToReturn;
        }

        public static string ToProtocolString(byte b)
        {
            switch (b)
            {
                case 1:
                    return "ICMP";
                case 2:
                    return "IGMP";
                case 6:
                    return "TCP";
                case 8:
                    return "EGP";
                case 17:
                    return "UDP";
                case 41:
                    return "ENCAP";
                case 63:
                    return "Any local network";
                case 70:
                    return "VISA";
                case 89:
                    return "OSPF";
                case 91:
                    return "LARP";
                case 92:
                    return "MTP";
                case 101:
                    return "IFMP";
                case 113:
                    return "PGM";
                case 115:
                    return "L2TP";
                case 117:
                    return "IATP";
                case 123:
                    return "PTP";
                case 124:
                    return "IS-IS over IPv4";
                case 125:
                    return "FIRE";
                case 126:
                    return "CRTP";
                case 127:
                    return "CRUDP";
                case 128:
                    return "SSCOPMCE";
                case 132:
                    return "SCTP";
                case byte n when(n >= 143 && n <= 252):
                    return "UNASSIGNED";
                case byte n when (n >= 253 && n <= 254):
                    return "EXPERIMENTATION";
                case 255:
                    return "Reserved";
                default:
                    return "#" + b.ToString();
            }
        }
    }
}
