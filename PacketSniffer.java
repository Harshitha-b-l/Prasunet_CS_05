import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.ArrayList;
import java.util.List;

public class PacketSniffer {

    public static void main(String[] args) {
        List<PcapIf> allDevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();

        // Get a list of devices
        int r = Pcap.findAllDevs(allDevs, errbuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : allDevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = allDevs.get(0); 
        int snaplen = 64 * 1024;           
        int flags = Pcap.MODE_PROMISCUOUS; 
        int timeout = 10 * 1000;           
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: %s", errbuf.toString());
            return;
        }

        PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Udp udp = new Udp();

                if (packet.hasHeader(ip)) {
                    byte[] sIP = new byte[4];
                    byte[] dIP = new byte[4];
                    ip.source(sIP);
                    ip.destination(dIP);

                    System.out.printf("IP Src: %s -> IP Dest: %s\n",
                            org.jnetpcap.packet.format.FormatUtils.ip(sIP),
                            org.jnetpcap.packet.format.FormatUtils.ip(dIP));

                    if (packet.hasHeader(tcp)) {
                        System.out.printf("Protocol: TCP Src Port: %d -> Dest Port: %d\n",
                                tcp.source(), tcp.destination());
                    } else if (packet.hasHeader(udp)) {
                        System.out.printf("Protocol: UDP Src Port: %d -> Dest Port: %d\n",
                                udp.source(), udp.destination());
                    }
                }
            }
        };

        pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "jNetPcap rocks!");

        pcap.close();
    }
}
