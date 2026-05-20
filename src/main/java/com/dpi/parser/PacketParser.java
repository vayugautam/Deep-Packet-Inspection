package com.dpi.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Packet Parser - Parses raw packets into readable structures
 */
public class PacketParser {

    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;
    public static final int PROTOCOL_ICMP = 1;

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    public static final int TCP_FLAG_SYN = 0x02;
    public static final int TCP_FLAG_ACK = 0x10;
    public static final int TCP_FLAG_FIN = 0x01;
    public static final int TCP_FLAG_RST = 0x04;
    public static final int TCP_FLAG_PSH = 0x08;

    /**
     * Parse raw packet into structured format
     */
    public static ParsedPacket parse(RawPacket rawPacket) {
        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec = (int) rawPacket.header.tsSeconds;
        parsed.timestampUsec = (int) rawPacket.header.tsMicroseconds;

        byte[] data = rawPacket.data;
        int offset = 0;

        // Parse Ethernet header (14 bytes)
        if (data.length < 14) {
            return parsed; // Packet too short
        }

        parsed.srcMac = bytesToMacString(Arrays.copyOfRange(data, 6, 12));
        parsed.destMac = bytesToMacString(Arrays.copyOfRange(data, 0, 6));

        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        parsed.etherType = etherType;

        offset = 14;

        // Parse IP header if present
        if (etherType == ETHERTYPE_IPV4 && data.length >= offset + 20) {
            int versionIhl = data[offset] & 0xFF;
            int version = (versionIhl >> 4) & 0x0F;
            int headerLen = (versionIhl & 0x0F) * 4;

            parsed.hasIp = true;
            parsed.ipVersion = version;
            parsed.ttl = data[offset + 8] & 0xFF;
            parsed.protocol = data[offset + 9] & 0xFF;

            parsed.srcIp = ipBytesToString(data, offset + 12);
            parsed.destIp = ipBytesToString(data, offset + 16);

            offset += headerLen;

            // Parse transport layer
            if (parsed.protocol == PROTOCOL_TCP && data.length >= offset + 20) {
                parsed.hasTcp = true;
                ByteBuffer bb = ByteBuffer.wrap(data, offset, 20).order(ByteOrder.BIG_ENDIAN);

                parsed.srcPort = bb.getShort() & 0xFFFF;
                parsed.destPort = bb.getShort() & 0xFFFF;
                parsed.seqNumber = bb.getInt();
                parsed.ackNumber = bb.getInt();

                byte dataOffset = bb.get();
                int tcpHeaderLen = ((dataOffset >> 4) & 0x0F) * 4;

                parsed.tcpFlags = bb.get() & 0xFF;

                offset += tcpHeaderLen;

            } else if (parsed.protocol == PROTOCOL_UDP && data.length >= offset + 8) {
                parsed.hasUdp = true;
                ByteBuffer bb = ByteBuffer.wrap(data, offset, 8).order(ByteOrder.BIG_ENDIAN);

                parsed.srcPort = bb.getShort() & 0xFFFF;
                parsed.destPort = bb.getShort() & 0xFFFF;

                offset += 8;
            }
        }

        // Remaining data is payload
        parsed.payloadLength = data.length - offset;
        if (parsed.payloadLength > 0) {
            parsed.payloadData = Arrays.copyOfRange(data, offset, data.length);
        } else {
            parsed.payloadData = new byte[0];
        }

        return parsed;
    }

    private static String bytesToMacString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private static String ipBytesToString(byte[] data, int offset) {
        return String.format("%d.%d.%d.%d",
                data[offset] & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF);
    }

    public static String protocolToString(byte protocol) {
        switch (protocol) {
            case PROTOCOL_TCP:
                return "TCP";
            case PROTOCOL_UDP:
                return "UDP";
            case PROTOCOL_ICMP:
                return "ICMP";
            default:
                return "Unknown(" + (protocol & 0xFF) + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_FLAG_RST) != 0) sb.append("RST ");
        if ((flags & TCP_FLAG_PSH) != 0) sb.append("PSH ");
        return sb.toString().trim();
    }
}
