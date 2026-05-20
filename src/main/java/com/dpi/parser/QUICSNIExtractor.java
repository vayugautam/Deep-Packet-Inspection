package com.dpi.parser;

import java.util.Optional;

/**
 * QUICSNIExtractor - Extracts Server Name Indication (SNI) from QUIC Initial packets
 */
public class QUICSNIExtractor {

    public static boolean isQUICInitial(byte[] payload, int offset, int length) {
        if (length < 5 || payload == null || offset + 5 > payload.length) {
            return false;
        }

        // QUIC long header starts with 1 bit set (form bit)
        byte firstByte = payload[offset];
        return (firstByte & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQUICInitial(payload, offset, length)) {
            return Optional.empty();
        }

        int endLimit = offset + length;
        if (endLimit > payload.length) {
            endLimit = payload.length;
        }

        // Search for TLS Client Hello pattern within the QUIC packet
        // Look for the handshake type byte (0x01) followed by SNI extension
        for (int i = offset; i + 50 < endLimit; i++) {
            if (payload[i] == 0x01) { // Client Hello handshake type
                // Try to extract SNI starting from here (C++ uses payload + i - 5)
                int checkOffset = i - 5;
                if (checkOffset >= offset) {
                    Optional<String> result = SNIExtractor.extract(payload, checkOffset, endLimit - checkOffset);
                    if (result.isPresent()) {
                        return result;
                    }
                }
            }
        }

        return Optional.empty();
    }
}
