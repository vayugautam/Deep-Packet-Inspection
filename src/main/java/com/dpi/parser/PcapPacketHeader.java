package com.dpi.parser;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * PCAP Packet Header - 16 bytes before each packet
 */
public class PcapPacketHeader {
    public static final int SIZE = 16;

    public long tsSeconds;   // Timestamp seconds
    public long tsMicroseconds; // Timestamp microseconds
    public long inclLen;     // Bytes saved in file
    public long origLen;     // Original packet length

    public static PcapPacketHeader read(DataInputStream dis, ByteOrder order) throws IOException {
        PcapPacketHeader header = new PcapPacketHeader();
        byte[] buffer = new byte[16];
        dis.readFully(buffer);

        ByteBuffer bb = ByteBuffer.wrap(buffer).order(order);

        header.tsSeconds = bb.getInt() & 0xFFFFFFFFL;
        header.tsMicroseconds = bb.getInt() & 0xFFFFFFFFL;
        header.inclLen = bb.getInt() & 0xFFFFFFFFL;
        header.origLen = bb.getInt() & 0xFFFFFFFFL;

        return header;
    }
}
