package com.dpi.parser;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * PCAP Global Header - The first 24 bytes of a PCAP file
 */
public class PcapGlobalHeader {
    public static final int SIZE = 24;
    public static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    public static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    public long magicNumber;      // 0xa1b2c3d4
    public int versionMajor;      // Usually 2
    public int versionMinor;      // Usually 4
    public int timezone;          // GMT offset (usually 0)
    public int sigfigs;           // Timestamp accuracy (usually 0)
    public long snaplen;          // Max packet length
    public long network;          // Data link type (1=Ethernet)

    public static PcapGlobalHeader read(DataInputStream dis, ByteOrder order) throws IOException {
        PcapGlobalHeader header = new PcapGlobalHeader();
        byte[] buffer = new byte[24];
        dis.readFully(buffer);

        ByteBuffer bb = ByteBuffer.wrap(buffer).order(order);

        header.magicNumber = bb.getInt() & 0xFFFFFFFFL;
        header.versionMajor = bb.getShort() & 0xFFFF;
        header.versionMinor = bb.getShort() & 0xFFFF;
        header.timezone = bb.getInt();
        header.sigfigs = bb.getInt();
        header.snaplen = bb.getInt() & 0xFFFFFFFFL;
        header.network = bb.getInt() & 0xFFFFFFFFL;

        return header;
    }

    @Override
    public String toString() {
        return String.format("PCAP Header: v%d.%d, snaplen=%d, link_type=%d",
                versionMajor, versionMinor, snaplen, network);
    }
}
