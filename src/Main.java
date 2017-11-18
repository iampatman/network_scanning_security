
import java.io.*;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import jpcap.*;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author PC
 */
public class Main {
    public static String PortService(int port){
        String str;
        switch (port){
            case 80: 
                str =  "HTTP";
                break;
            case 53: 
                str =  "DNS";
            case 20:
            case 21:
                str = "FTP";
                break;
            case 22:
                str = "SSH";
                break;
            case 23: 
                str = "TELNET";
                break;
            case 25: 
                str = "SMTP";
                break;
            case 100: 
                str = "POP3";
                break;
            case 143:
                str = "IMAP";
                break;
            case 443:
                str = "HTTPS";
                break;
                default: str = null;
        }        
        return str;
    }
    
    @SuppressWarnings("unchecked")
    public static void main(String[] args){
        
        try{
            int threshold;
            String filepath;
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Please enter the path of the trace file needed to be scan: ");
            filepath = in.readLine();
            File f = new File(filepath);
            if (f.exists()==false){
                System.out.println("File not found!");
                return;
            }
            
            JpcapCaptor reader;            
            reader = JpcapCaptor.openFile(filepath);            
            List<SourceAnalyst> list = new ArrayList<SourceAnalyst>();            
            List portList = new ArrayList<>();
            Packet packet;
            MyPacket mypacket;
            System.out.print("Please enter the scanning threshold: ");
            threshold = Integer.parseInt(in.readLine());
            boolean finish=false;
            System.out.println("The hosts form those source ip are scanning: ");
            while (finish==false){
                packet = reader.getPacket();                
                if (packet==null) {
                    finish=true;
                }
                if (packet==null||(packet.getClass()!=TCPPacket.class&&packet.getClass()!=UDPPacket.class)) {
                    continue;
                }                 
                mypacket = new MyPacket(packet);                    
                InetAddress src_ip = mypacket.getSourceIP();
                InetAddress dest_ip = mypacket.getDestinationIP();
                int dest_port = mypacket.getDestinationPort();
                if (dest_port<1000&&portList.contains(dest_port)==false){
                    portList.add(dest_port);
                }
                int i;
                for (i=0;i<list.size();i++) {                   
                    SourceAnalyst t = list.get(i);
                    if (t.sameIP(src_ip, dest_ip)){
                        if (mypacket.getSyn()) {
                            t.incSynNumber();
                        }
                        break;
                    }
                    else if (t.sameIP(dest_ip, src_ip)){
                        if (mypacket.getAck()) {
                            t.incAckNumber();
                        }
                        break;
                    }
                }                
                if (i==list.size()){
                    SourceAnalyst src = new SourceAnalyst(src_ip, dest_ip, threshold);
                    if (mypacket.getSyn()) {
                        src.incSynNumber();
                    }
                    else if (mypacket.getAck()){
                        src.incAckNumber();
                    }
                    list.add(src);
                    
                } else if (list.get(i).isScanning()&&list.get(i).isPrinted()==false){
                    System.out.println(list.get(i).getSourceIp() + " is scanning " + list.get(i).getDestinationIp());
                    
                    list.get(i).setPrinted(true);
                }                
            }
            reader.close();                 


            //Cac dich vu dang hoat dong
            System.out.println("The services are running on this computer: ");            
            for (int i=0;i<portList.size();i++){        
                String srv = PortService((int)portList.get(i));
                if (srv!=null){                        
                    System.out.println(srv);
                }
            }
            
            
            
        } catch(Exception e){
            System.out.println(e.toString());
        }
        
    }
}

/*
for (int i = 0; i < lSrcIP.size(); i++) {
    if (lSrcIP.get(i).getAttacker().equals(srcIP) && lSrcIP.get(i).getVictim().equals(dstIP)) {
        if (newPacket.getSyn()) {
            lSrcIP.get(i).addSyn();
        }
        i
       sSamIP = true;
        break;
    } else if (lSrcIP.get(i).getAttacker().equals(dstIP) && lSrcIP.get(i).getVictim().equals(srcIP)) {
            if (newPacket.getAck()) {
            lSrcIP.get(i).addAck();
        }
    isSamIP = true;
    break;
    }
    */ 