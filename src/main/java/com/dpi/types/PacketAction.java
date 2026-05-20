package com.dpi.types;

/**
 * Packet action enumeration
 * Defines what to do with a packet
 */
public enum PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
