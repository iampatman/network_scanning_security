
import java.net.Inet4Address;
import java.net.InetAddress;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author PC
 */
public class SourceAnalyst {
    private InetAddress src_ip;
    private InetAddress dest_ip;
    private int syn;
    private int ack;  
    private int threshold;
    private boolean printed;
    public SourceAnalyst(InetAddress src_ip,InetAddress dest_ip, int th) {
        this.src_ip = src_ip;
        this.dest_ip = dest_ip;
        this.syn = 0;
        this.ack = 0;
        this.threshold = th;     
        this.printed = false;
    }
    public int getAck(){
        return ack;        
    }
    public int getSyn(){
        return syn;
    }
    public void incSynNumber(){
        this.syn++;
    }
    public void incAckNumber(){
        this.ack++;
    }
    public boolean isScanning(){
        if (ack!=0&&(1.0*syn/ack)>=threshold){            
            return true;
        }
        else {            
            return false;
            
        }
    }
    public boolean sameIP(InetAddress src_ip,InetAddress dest_ip){
        if (this.src_ip.getHostAddress().equals(src_ip.getHostAddress())&&
                this.dest_ip.getHostAddress().equals(dest_ip.getHostAddress())){
            return true;
        }
        else {
            return false;
        }
    }
    public InetAddress getSourceIp(){
        return this.src_ip;
    }
    public InetAddress getDestinationIp(){
        return this.dest_ip;
    }

    public boolean isPrinted() {
        return printed;
    }

    public void setPrinted(boolean printed) {
        this.printed = printed;
    }
    
    
    
    
}
