package com.dpi.parser;

import java.util.Optional;

/**
 * SNI Extractor - Parses TLS Client Hello to extract Server Name Indication
 * 
 * TLS Client Hello Structure:
 * - Record: Type (1) + Version (2) + Length (2)
 * - Handshake: Type (1) + Length (3)
 * - ClientHello: Version (2) + Random (32) + SessionIDLen (1) + SessionID (var)
 *               + CipherSuitesLen (2) + CipherSuites (var)
 *               + CompressionLen (1) + Compression (var)
 *               + ExtensionsLen (2) + Extensions (var)
 * 
 * SNI Extension: Type (2) + Length (2) + SNIListLen (2) + SNIType (1) + SNILen (2) + SNI (var)
 */
public class SNIExtractor {

    private static final byte TLS_RECORD_HANDSHAKE = 0x16;
    private static final byte HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    private static final short SNI_EXTENSION_TYPE = 0x0000;

    /**
     * Extract SNI from TLS Client Hello packet
     * payload should point to the TCP payload (after TCP header)
     */
    public static Optional<String> extract(byte[] payload) {
        return extract(payload, 0, payload != null ? payload.length : 0);
    }

    /**
     * Extract SNI from TLS Client Hello packet starting at offset with length
     */
    public static Optional<String> extract(byte[] payload, int startOffset, int length) {
        if (payload == null || length < 43 || startOffset + length > payload.length) {
            return Optional.empty();
        }

        int offset = startOffset;
        int endLimit = startOffset + length;

        // Parse TLS Record Header
        if (offset >= endLimit) return Optional.empty();
        byte recordType = payload[offset];
        if (recordType != TLS_RECORD_HANDSHAKE) {
            return Optional.empty();
        }

        offset += 1; // Record type
        offset += 2; // Version

        // Record length (2 bytes, big-endian)
        if (offset + 2 > endLimit) return Optional.empty();
        int recordLength = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;

        // Parse Handshake Header
        if (offset >= endLimit) return Optional.empty();
        byte handshakeType = payload[offset];
        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return Optional.empty();
        }

        offset += 1; // Handshake type

        // Handshake length (3 bytes, big-endian)
        if (offset + 3 > endLimit) return Optional.empty();
        int handshakeLength = ((payload[offset] & 0xFF) << 16) |
                             ((payload[offset + 1] & 0xFF) << 8) |
                             (payload[offset + 2] & 0xFF);
        offset += 3;

        // Parse ClientHello
        // Version (2 bytes)
        if (offset + 2 > endLimit) return Optional.empty();
        offset += 2;

        // Random (32 bytes)
        if (offset + 32 > endLimit) return Optional.empty();
        offset += 32;

        // Session ID Length (1 byte)
        if (offset >= endLimit) return Optional.empty();
        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;

        // Cipher Suites Length (2 bytes, big-endian)
        if (offset + 2 > endLimit) return Optional.empty();
        int cipherSuitesLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2 + cipherSuitesLen;

        // Compression Methods Length (1 byte)
        if (offset >= endLimit) return Optional.empty();
        int compressionLen = payload[offset] & 0xFF;
        offset += 1 + compressionLen;

        // Extensions Length (2 bytes, big-endian)
        if (offset + 2 > endLimit) return Optional.empty();
        int extensionsLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;

        // Parse Extensions
        int extensionsEnd = offset + extensionsLen;
        if (extensionsEnd > endLimit) {
            extensionsEnd = endLimit;
        }

        while (offset + 4 <= extensionsEnd) {
            int extensionType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2;

            int extensionLength = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2;

            if (extensionType == SNI_EXTENSION_TYPE) {
                // Found SNI extension, parse it
                return parseSNIExtension(payload, offset, extensionLength);
            }

            offset += extensionLength;
        }

        return Optional.empty();
    }

    private static Optional<String> parseSNIExtension(byte[] payload, int offset, int length) {
        if (offset + 2 > payload.length || offset + length > payload.length) {
            return Optional.empty();
        }

        // SNI List Length (2 bytes, big-endian)
        int sniListLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;

        if (offset + 3 > payload.length) {
            return Optional.empty();
        }

        // SNI Type (1 byte) - 0x00 for hostname
        byte sniType = payload[offset];
        offset += 1;

        if (sniType != 0x00) {
            return Optional.empty();
        }

        // SNI Length (2 bytes, big-endian)
        if (offset + 2 > payload.length) {
            return Optional.empty();
        }
        int sniLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;

        if (offset + sniLen > payload.length) {
            return Optional.empty();
        }

        // Extract SNI string
        String sni = new String(payload, offset, sniLen);
        return Optional.of(sni);
    }
}
