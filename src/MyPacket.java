
import java.net.InetAddress;
import jpcap.packet.ARPPacket;
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
public class MyPacket {
    private Packet mypacket;
    private TCPPacket mytcppacket;
    private UDPPacket myudppacket;    
    
    public MyPacket(Packet p){
        mypacket = p;
        if (p.getClass()==TCPPacket.class){
            mytcppacket = (TCPPacket)p;
            myudppacket = null;
        } else{
            mytcppacket = null;
            myudppacket = (UDPPacket)p;
        }        
    }
    public boolean isUDPPacket(){
        if (mytcppacket!=null) {
            return false;
        }
        else {
            return true;
        }
    }
    public boolean isTCPPacket(){
        if (mytcppacket!=null) {
            return true;
        }
        else {
            return false;
        }
    }
    public int getSourcePort(){
        if (mytcppacket!=null) {
            return mytcppacket.src_port;
        }
        else {
            return myudppacket.src_port;
        }
    }
    public int getDestinationPort(){
        if (mytcppacket!=null) {
            return mytcppacket.dst_port;
        }
        else {
            return myudppacket.dst_port;
        }
    }
    public boolean getSyn(){
        if (mytcppacket!=null) {
            return mytcppacket.syn;
        } else {
            return false;
        }
    }
    public boolean getAck(){
        if (mytcppacket!=null&&mytcppacket.syn) {
            return mytcppacket.ack;
        } else {
            return false;
        }
    }
    public InetAddress getSourceIP(){
        if (mytcppacket!=null) {
            return mytcppacket.src_ip;
        } else {
            return myudppacket.src_ip;
        }
    }
    public InetAddress getDestinationIP(){
        if (mytcppacket!=null) {
            return mytcppacket.dst_ip;            
        } else {
            return myudppacket.dst_ip;            
        }
    }
    
    
}
