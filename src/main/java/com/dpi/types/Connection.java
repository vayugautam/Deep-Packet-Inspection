package com.dpi.types;

import java.time.Instant;
import java.io.Serializable;

/**
 * Connection Entry - tracks a network flow
 */
public class Connection implements Serializable {
    private FiveTuple tuple;
    private ConnectionState state;
    private AppType appType;
    private String sni;  // Server Name Indication
    
    private long packetsIn;
    private long packetsOut;
    private long bytesIn;
    private long bytesOut;
    
    private Instant firstSeen;
    private Instant lastSeen;
    
    private PacketAction action;
    
    // TCP state tracking
    private boolean synSeen;
    private boolean synAckSeen;
    private boolean finSeen;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        this.state = ConnectionState.NEW;
        this.appType = AppType.UNKNOWN;
        this.sni = "";
        this.action = PacketAction.FORWARD;
        
        this.packetsIn = 0;
        this.packetsOut = 0;
        this.bytesIn = 0;
        this.bytesOut = 0;
        
        this.firstSeen = Instant.now();
        this.lastSeen = this.firstSeen;
        
        this.synSeen = false;
        this.synAckSeen = false;
        this.finSeen = false;
    }

    public void updateOutbound(long packetSize) {
        packetsOut++;
        bytesOut += packetSize;
        lastSeen = Instant.now();
    }

    public void updateInbound(long packetSize) {
        packetsIn++;
        bytesIn += packetSize;
        lastSeen = Instant.now();
    }

    // Getters and setters
    public FiveTuple getTuple() { return tuple; }
    public ConnectionState getState() { return state; }
    public void setState(ConnectionState state) { this.state = state; }
    
    public AppType getAppType() { return appType; }
    public void setAppType(AppType appType) { this.appType = appType; }
    
    public String getSni() { return sni; }
    public void setSni(String sni) { this.sni = sni != null ? sni : ""; }
    
    public long getPacketsIn() { return packetsIn; }
    public long getPacketsOut() { return packetsOut; }
    public long getBytesIn() { return bytesIn; }
    public long getBytesOut() { return bytesOut; }
    
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    
    public PacketAction getAction() { return action; }
    public void setAction(PacketAction action) { this.action = action; }
    
    public boolean isSynSeen() { return synSeen; }
    public void setSynSeen(boolean synSeen) { this.synSeen = synSeen; }
    
    public boolean isSynAckSeen() { return synAckSeen; }
    public void setSynAckSeen(boolean synAckSeen) { this.synAckSeen = synAckSeen; }
    
    public boolean isFinSeen() { return finSeen; }
    public void setFinSeen(boolean finSeen) { this.finSeen = finSeen; }

    @Override
    public String toString() {
        return String.format("Connection{tuple=%s, app=%s, state=%s, bytes_in=%d, bytes_out=%d}",
                tuple, appType, state, bytesIn, bytesOut);
    }
}
