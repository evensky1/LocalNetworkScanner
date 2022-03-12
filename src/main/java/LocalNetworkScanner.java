import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LocalNetworkScanner {

    public static void main(String[] args) throws IOException, PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

        ExecutorService pool = Executors.newFixedThreadPool(4);

        for (PcapNetworkInterface nif : interfaces) {
            if (!nif.getAddresses().isEmpty()) {
                PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
                PcapHandle sendHandle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

                PacketListener listener = packet -> {
                    if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                            System.out.println(arp.getHeader().getSrcHardwareAddr()
                                    + " resolved to "
                                    + arp.getHeader().getSrcProtocolAddr().toString()
                                    + " its name is "
                                    + parseOui(arp.getHeader().getSrcHardwareAddr().getOui().valueAsString()));
                        }
                    }
                };

                pool.execute(new LocalNetworkScanner.Task(handle, listener));

                MacAddress srcMac = MacAddress.getByName(nif.getLinkLayerAddresses().get(0).toString());
                byte[] rawMaskAddr = nif.getAddresses().get(1).getNetmask().getAddress();
                byte[] rawInetAddr = nif.getAddresses().get(1).getAddress().getAddress();
                byte[] resultAddr = new byte[4];

                for (int i = 0; i < 4; i++) {
                    resultAddr[i] = (byte) (rawMaskAddr[i] & rawInetAddr[i]);
                }

                ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
                arpBuilder
                        .hardwareType(ArpHardwareType.ETHERNET)
                        .protocolType(EtherType.IPV4)
                        .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                        .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                        .operation(ArpOperation.REQUEST)
                        .srcHardwareAddr(srcMac)
                        .srcProtocolAddr(InetAddress.getByAddress(rawInetAddr))
                        .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS);

                EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
                etherBuilder
                        .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                        .srcAddr(srcMac)
                        .type(EtherType.ARP)
                        .paddingAtBuild(true);


                byte[] topBorderBytes = new byte[4];

                for (int i = 0; i < 4; i++) {
                    topBorderBytes[i] = (byte) (rawMaskAddr[i] ^ 255);
                }

                int topBorder = byteArrayToInt(topBorderBytes);
                int currentAddr = byteArrayToInt(resultAddr);

                for (int i = 0; i < topBorder; i++) {
                    currentAddr++;

                    arpBuilder.dstProtocolAddr(
                            InetAddress.getByAddress(intToByteArray(currentAddr))
                    );

                    Packet p = etherBuilder
                            .payloadBuilder(arpBuilder)
                            .build();

                    try {
                        sendHandle.sendPacket(p);
                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }

                }

                sendHandle.close();
            }
        }
        pool.shutdown();
    }

    private static byte[] intToByteArray(int n) {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++) {
            res[3 - i] = (byte) ((n >> i * 8) & 255);
        }
        return res;
    }

    private static int byteArrayToInt(byte[] b) {
        int dt = 0;
        int start = 0;
        for (int i = 0; i < 4; i++) {
            dt = (dt << 8) + (b[start++] & 255);
        }
        return dt;
    }

    private static String parseOui(String oui) {
        switch (oui) {
            case "48-57-02":
                return "Huawei";
            case "38-22-e2":
                return "Hewlett-Packard";
            case "7c-03-ab":
                return "Xiaomi";
            case "00-50-56":
                return "VMWare";
            default:
                return "unknown";
        }
    }

    private static class Task implements Runnable {
        private final PcapHandle handle;
        private final PacketListener listener;

        public Task(PcapHandle handle, PacketListener listener) {
            this.handle = handle;
            this.listener = listener;
        }

        @Override
        public void run() { //The thread may not terminate if the number of captured packets is less than packetCount
            try {
                handle.loop(260, listener);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                e.printStackTrace();
            }
            handle.close();
        }
    }
}