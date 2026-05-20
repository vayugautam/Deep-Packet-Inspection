package com.dpi.parser;

/**
 * Parsed packet representation
 */
public class ParsedPacket {
    public int timestampSec;
    public int timestampUsec;

    public String srcMac;
    public String destMac;
    public int etherType;

    public boolean hasIp;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol;
    public int ttl;

    public boolean hasTcp;
    public boolean hasUdp;
    public int srcPort;
    public int destPort;
    public int tcpFlags;
    public int seqNumber;
    public int ackNumber;

    public int payloadLength;
    public byte[] payloadData;
}
