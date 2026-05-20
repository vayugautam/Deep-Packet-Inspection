package com.dpi.parser;

/**
 * Represents a raw packet from PCAP file
 */
public class RawPacket {
    public PcapPacketHeader header;
    public byte[] data;

    public RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }
}
