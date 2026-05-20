package com.dpi.parser;

import java.util.Optional;

/**
 * DNSExtractor - Extracts queried domain from DNS request packets
 */
public class DNSExtractor {

    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        // Minimum DNS header is 12 bytes
        if (length < 12 || payload == null || offset + 12 > payload.length) {
            return false;
        }

        // Check QR bit (byte 2, bit 7) in DNS flags - should be 0 for query
        byte flags = payload[offset + 2];
        if ((flags & 0x80) != 0) {
            return false; // It is a response
        }

        // Check QDCOUNT (bytes 4-5) - should be > 0
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount > 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int endLimit = offset + length;
        if (endLimit > payload.length) {
            endLimit = payload.length;
        }

        // DNS query section starts at byte 12 of the DNS payload
        int currentOffset = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (currentOffset < endLimit) {
            int labelLength = payload[currentOffset] & 0xFF;

            // 0 length signifies end of domain name
            if (labelLength == 0) {
                break;
            }

            // If it is a compression pointer or invalid length (> 63)
            if (labelLength > 63) {
                break;
            }

            currentOffset++;
            if (currentOffset + labelLength > endLimit) {
                break;
            }

            if (domain.length() > 0) {
                domain.append('.');
            }

            domain.append(new String(payload, currentOffset, labelLength));
            currentOffset += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
