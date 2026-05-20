package com.dpi.types;

/**
 * Connection state enumeration
 */
public enum ConnectionState {
    NEW,           // Connection just discovered
    ESTABLISHED,   // TCP handshake complete
    CLASSIFIED,    // Application type identified
    BLOCKED,       // Marked for blocking
    CLOSED         // Connection closed
}
