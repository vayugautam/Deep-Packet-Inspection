package com.dpi.parser;

import java.io.*;
import java.nio.ByteOrder;
import java.nio.ByteBuffer;

/**
 * PCAP File Reader
 * Reads packets from PCAP files with automatic byte-order detection
 */
public class PcapReader {
    private DataInputStream dis;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap;
    private String filename;

    public boolean open(String filename) throws IOException {
        this.filename = filename;
        close();

        try {
            dis = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));

            // Read global header to detect byte order
            byte[] headerBuffer = new byte[PcapGlobalHeader.SIZE];
            dis.readFully(headerBuffer);

            // Check magic number (first 4 bytes)
            ByteOrder order;
            long magic = ((headerBuffer[0] & 0xFF) << 24) |
                         ((headerBuffer[1] & 0xFF) << 16) |
                         ((headerBuffer[2] & 0xFF) << 8) |
                         (headerBuffer[3] & 0xFF);

            if (magic == PcapGlobalHeader.PCAP_MAGIC_NATIVE) {
                order = ByteOrder.BIG_ENDIAN;
                needsByteSwap = false;
            } else if (magic == PcapGlobalHeader.PCAP_MAGIC_SWAPPED) {
                order = ByteOrder.LITTLE_ENDIAN;
                needsByteSwap = true;
            } else {
                System.err.println("Invalid PCAP magic number: 0x" + Long.toHexString(magic));
                close();
                return false;
            }

            // Reparse with detected byte order
            ByteBuffer bb = ByteBuffer.wrap(headerBuffer).order(order);
            globalHeader = PcapGlobalHeader.read(new DataInputStream(new ByteArrayInputStream(headerBuffer)), order);

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + 
                             (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;

        } catch (IOException e) {
            System.err.println("Error opening PCAP file: " + e.getMessage());
            close();
            return false;
        }
    }

    public void close() {
        if (dis != null) {
            try {
                dis.close();
            } catch (IOException e) {
                // Ignore
            }
            dis = null;
        }
    }

    public boolean readNextPacket(RawPacket packet) throws IOException {
        if (dis == null) {
            return false;
        }

        try {
            ByteOrder order = needsByteSwap ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
            
            // Read packet header
            byte[] headerBuffer = new byte[PcapPacketHeader.SIZE];
            dis.readFully(headerBuffer);

            PcapPacketHeader header = PcapPacketHeader.read(
                new DataInputStream(new ByteArrayInputStream(headerBuffer)), order);

            // Read packet data
            byte[] data = new byte[(int) header.inclLen];
            dis.readFully(data);

            packet.header = header;
            packet.data = data;
            return true;

        } catch (EOFException e) {
            return false;
        }
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return dis != null;
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
}

// Helper classes
class ByteArrayInputStream extends InputStream {
    byte[] buf;
    int pos = 0;

    ByteArrayInputStream(byte[] data) {
        this.buf = data;
    }

    @Override
    public int read() {
        if (pos < buf.length) {
            return buf[pos++] & 0xFF;
        }
        return -1;
    }

    @Override
    public int read(byte[] b, int off, int len) {
        int available = buf.length - pos;
        if (available <= 0) return -1;
        int toRead = Math.min(len, available);
        System.arraycopy(buf, pos, b, off, toRead);
        pos += toRead;
        return toRead;
}
