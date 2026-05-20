package com.dpi.types;

import java.io.Serializable;
import java.util.Objects;

/**
 * Five-Tuple: Uniquely identifies a connection/flow
 * Consists of: src_ip, dst_ip, src_port, dst_port, protocol
 */
public class FiveTuple implements Serializable, Comparable<FiveTuple> {
    private final long srcIp;      // 32-bit IP as long
    private final long dstIp;      // 32-bit IP as long
    private final int srcPort;     // 16-bit port
    private final int dstPort;     // 16-bit port
    private final byte protocol;   // TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, byte protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /**
     * Create reverse tuple (for matching bidirectional flows)
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * Convert 32-bit IP (as long) to human-readable format
     */
    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    /**
     * Parse IP string to 32-bit long
     */
    public static long parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP format");
        
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | (Integer.parseInt(parts[i]) & 0xFF);
        }
        return result;
    }

    @Override
    public String toString() {
        String protocolName = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return String.format("%s:%d -> %s:%d (%s)",
                ipToString(srcIp), srcPort,
                ipToString(dstIp), dstPort,
                protocolName);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple tuple = (FiveTuple) o;
        return srcIp == tuple.srcIp &&
               dstIp == tuple.dstIp &&
               srcPort == tuple.srcPort &&
               dstPort == tuple.dstPort &&
               protocol == tuple.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public int compareTo(FiveTuple o) {
        if (srcIp != o.srcIp) return Long.compare(srcIp, o.srcIp);
        if (dstIp != o.dstIp) return Long.compare(dstIp, o.dstIp);
        if (srcPort != o.srcPort) return Integer.compare(srcPort, o.srcPort);
        if (dstPort != o.dstPort) return Integer.compare(dstPort, o.dstPort);
        return Byte.compare(protocol, o.protocol);
    }

    // Getters
    public long getSrcIp() { return srcIp; }
    public long getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public byte getProtocol() { return protocol; }
}
