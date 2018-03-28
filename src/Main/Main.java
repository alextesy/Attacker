package Main;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.util.PcapPacketArrayList;


import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by IL984626 on 26/03/2018.
 */
public class Main {
    public static boolean first=true;
    public static long time;
    public static long currentTime;

    public static void main(String[] args) throws InterruptedException {
      // attacker((long) (Double.parseDouble(args[0])*1000 ),Integer.parseInt(args[1]),Long.parseLong(args[2]),Integer.parseInt(args[3]),args[4],args[5],args[6]);
        attacker((long) (Double.parseDouble("1522180000.400")*1000 ),168,5000,10300, "34:02:86:57:6a:0c","5sec.pcap","alex.txt");

    }
    public static void attacker(long start_time,int numOfBits,long window,int cutoff,String macID,String pacpPath,String outputPath ){

        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pacpPath, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        PcapPacketHandler<PcapPacketArrayList> handler = new PcapPacketHandler<PcapPacketArrayList>() {

            @Override
            public void nextPacket(PcapPacket pcapPacket, PcapPacketArrayList pcapPackets) {
                pcapPackets.add(pcapPacket);
            }


        };
        PcapPacketArrayList packets = new PcapPacketArrayList();

        pcap.loop(pcap.LOOP_INFINITE,handler,packets);
        pcap.close();
        List<Integer> byteArr=new ArrayList<>();
        long windowStartTime=start_time;
        int bytesSize=0;
        boolean first=true;
        long check=packets.get(0).getCaptureHeader().timestampInMillis();
        for (PcapPacket packet:packets) {
            Ethernet ethernet=packet.getHeader(new Ethernet());
            byte[] macDest=ethernet.destination();
            String packetMac=toHex(macDest);
            if(!packetMac.equals(macID))
                continue;
            if(packet.getCaptureHeader().timestampInMillis()<start_time) {
                continue;
            }
            else {
                if(windowStartTime+window>packet.getCaptureHeader().timestampInMillis()) {
                    bytesSize+=packet.getTotalSize();
                }
                else{
                    bytesSize=(bytesSize/(int)window)*1000;
                    if(bytesSize>cutoff)
                        byteArr.add(1);
                    else
                        byteArr.add(0);
                    if(byteArr.size()==numOfBits)
                        break;

                    bytesSize=packet.getTotalSize();
                    windowStartTime+=window;
                }

            }
        }
        int k=0;
        String message="";
        String temp="";
        for (Integer num:byteArr) {
            if(k==8) {
                //temp+=num;
                char letter = (char) Integer.parseInt(temp, 2);
                temp=""+num;
                message +=letter;
                k=1;
            }
            else{
                temp+=num;
                k++;
            }
        }
        message+=(char) Integer.parseInt(temp, 2);
        try (PrintWriter out = new PrintWriter(outputPath)) {
            out.println(message);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        System.out.println(message);


    }
    public static String toHex(byte[] arr){
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<arr.length;i++){
            sb.append(String.format("%02X", arr[i]));
            if(i!=arr.length-1)
                sb.append(":");
        }

        return sb.toString().toLowerCase();
    }

}
