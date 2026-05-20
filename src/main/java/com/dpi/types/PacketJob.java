package com.dpi.types;

import java.io.Serializable;

/**
 * PacketJob - Wraps packet data and parsing offsets for pipeline processing
 */
public class PacketJob implements Serializable {
    public long packetId;
    public long tsSec;
    public long tsUsec;
    public FiveTuple tuple;
    public byte tcpFlags;

    // Raw packet bytes
    public byte[] data;

    // Protocol offsets and lengths
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = 0;
    public int payloadLength = 0;

    public PacketJob() {
    }

    public PacketJob(long packetId, long tsSec, long tsUsec, FiveTuple tuple, byte tcpFlags, byte[] data) {
        this.packetId = packetId;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.tuple = tuple;
        this.tcpFlags = tcpFlags;
        this.data = data;
    }

    /**
     * Get TCP flags as standard string representation (e.g. SYN, ACK)
     */
    public String getTcpFlagsString() {
        StringBuilder sb = new StringBuilder();
        if ((tcpFlags & 0x01) != 0) sb.append("FIN ");
        if ((tcpFlags & 0x02) != 0) sb.append("SYN ");
        if ((tcpFlags & 0x04) != 0) sb.append("RST ");
        if ((tcpFlags & 0x08) != 0) sb.append("PSH ");
        if ((tcpFlags & 0x10) != 0) sb.append("ACK ");
        if ((tcpFlags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim();
    }
}
