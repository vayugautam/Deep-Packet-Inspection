package com.dpi.parser;

import java.util.Optional;

/**
 * HTTPHostExtractor - Extracts Host header from unencrypted HTTP request payload
 */
public class HTTPHostExtractor {

    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4 || payload == null || offset + 4 > payload.length) {
            return false;
        }

        // Compare first 4 bytes of payload against common HTTP methods
        for (String method : METHODS) {
            boolean match = true;
            for (int i = 0; i < 4; i++) {
                if (payload[offset + i] != (byte) method.charAt(i)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }

        return false;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) {
            return Optional.empty();
        }

        int endLimit = offset + length;
        if (endLimit > payload.length) {
            endLimit = payload.length;
        }

        // Search for case-insensitive "host:" header
        for (int i = offset; i + 5 < endLimit; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                payload[i + 4] == ':') {

                // Skip ':' and any whitespace
                int start = i + 5;
                while (start < endLimit && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find the end of the line (CR or LF)
                int end = start;
                while (end < endLimit && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    // Extract host string
                    String host = new String(payload, start, end - start).trim();
                    
                    // Remove port if present (e.g. host:port)
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    
                    return Optional.of(host);
                }
            }
        }

        return Optional.empty();
    }
}
