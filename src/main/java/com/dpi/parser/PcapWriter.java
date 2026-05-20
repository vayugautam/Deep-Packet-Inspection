package com.dpi.parser;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * PCAP Writer - Writes packets to PCAP files
 */
public class PcapWriter {
    private DataOutputStream dos;
    private long packetCounter = 0;

    public PcapWriter(String filename) throws IOException {
        dos = new DataOutputStream(new BufferedOutputStream(
            new FileOutputStream(filename)));
        
        // Write global header
        writePcapGlobalHeader();
    }

    private void writePcapGlobalHeader() throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) PcapGlobalHeader.PCAP_MAGIC_NATIVE);
        bb.putShort((short) 2);  // version major
        bb.putShort((short) 4);  // version minor
        bb.putInt(0);            // timezone
        bb.putInt(0);            // sigfigs
        bb.putInt(65535);        // snaplen
        bb.putInt(1);            // network (Ethernet)

        dos.write(bb.array());
        dos.flush();
    }

    public void writePacket(RawPacket packet) throws IOException {
        packetCounter++;

        ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) packet.header.tsSeconds);
        bb.putInt((int) packet.header.tsMicroseconds);
        bb.putInt((int) packet.header.inclLen);
        bb.putInt((int) packet.header.origLen);

        dos.write(bb.array());
        dos.write(packet.data);
    }

    public void close() throws IOException {
        if (dos != null) {
            dos.close();
        }
    }

    public long getPacketCount() {
        return packetCounter;
    }
}
