package com.dpi;

import com.dpi.parser.DNSExtractor;
import com.dpi.parser.HTTPHostExtractor;
import com.dpi.parser.SNIExtractor;
import org.junit.Test;
import java.util.Optional;
import static org.junit.Assert.*;

public class ProtocolExtractorTest {

    @Test
    public void testHTTPHostExtraction() {
        String httpPayload = "GET /index.html HTTP/1.1\r\n" +
                             "Host: www.google.com\r\n" +
                             "User-Agent: Mozilla/5.0\r\n\r\n";
        byte[] data = httpPayload.getBytes();

        assertTrue(HTTPHostExtractor.isHTTPRequest(data, 0, data.length));
        
        Optional<String> host = HTTPHostExtractor.extract(data, 0, data.length);
        assertTrue(host.isPresent());
        assertEquals("www.google.com", host.get());
    }

    @Test
    public void testDNSQueryExtraction() {
        // DNS Query header (12 bytes) + Query section
        // Transaction ID: 0x1234
        // Flags: 0x0100 (Standard Query)
        // Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
        byte[] dnsHeader = {
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        };
        // Query: google.com (6google3com0)
        byte[] query = {
            6, 'g', 'o', 'o', 'g', 'l', 'e',
            3, 'c', 'o', 'm',
            0,
            0x00, 0x01, // Type A
            0x00, 0x01  // Class IN
        };
        
        byte[] fullPayload = new byte[dnsHeader.length + query.length];
        System.arraycopy(dnsHeader, 0, fullPayload, 0, dnsHeader.length);
        System.arraycopy(query, 0, fullPayload, dnsHeader.length, query.length);

        assertTrue(DNSExtractor.isDNSQuery(fullPayload, 0, fullPayload.length));
        
        Optional<String> queryDomain = DNSExtractor.extractQuery(fullPayload, 0, fullPayload.length);
        assertTrue(queryDomain.isPresent());
        assertEquals("google.com", queryDomain.get());
    }

    @Test
    public void testSNIExtraction() {
        // Simple synthetic TLS Client Hello with SNI extension
        // TLS Record: Handshake (0x16), Version (0x0301), Length (0x00 0x30)
        // Handshake: ClientHello (0x01), Length (0x00 0x00 0x2c)
        // ClientHello: Version (0x0303), Random (32 bytes), SessionIDLen (0)
        // CipherSuitesLen (0x00 0x02), Cipher (0x00 0x2f)
        // CompressionLen (0x01), Comp (0x00)
        // ExtensionsLen (0x00 0x17)
        // SNI Extension: Type (0x0000), Len (0x0013), ListLen (0x0011), Type (0x00), SNILen (0x000e), SNI ("www.google.com")
        byte[] clientHello = new byte[5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 4 + 2 + 1 + 2 + 14];
        
        int offset = 0;
        // TLS Record Header
        clientHello[offset++] = 0x16; // Handshake
        clientHello[offset++] = 0x03; clientHello[offset++] = 0x01; // Version
        int recLenPos = offset;
        offset += 2; // Write record length later

        // Handshake Header
        clientHello[offset++] = 0x01; // ClientHello
        int handLenPos = offset;
        offset += 3; // Write handshake length later

        // ClientHello
        clientHello[offset++] = 0x03; clientHello[offset++] = 0x03; // Version
        offset += 32; // Random bytes (default 0)
        clientHello[offset++] = 0; // Session ID Length

        // Cipher suites
        clientHello[offset++] = 0; clientHello[offset++] = 2; // Cipher suites length
        clientHello[offset++] = 0x00; clientHello[offset++] = 0x2f; // Cipher suite

        // Compression
        clientHello[offset++] = 1; // Compression length
        clientHello[offset++] = 0; // Compression method

        // Extensions Length (2 bytes)
        int extLenPos = offset;
        offset += 2; // Write extensions length later

        // SNI Extension
        int extStart = offset;
        clientHello[offset++] = 0x00; clientHello[offset++] = 0x00; // SNI Type
        clientHello[offset++] = 0; clientHello[offset++] = 19; // SNI Extension Length (19 bytes)
        clientHello[offset++] = 0; clientHello[offset++] = 17; // SNI List Length (17 bytes)
        clientHello[offset++] = 0x00; // Server name type (host_name)
        clientHello[offset++] = 0; clientHello[offset++] = 14; // Host name length (14 bytes)
        
        String hostname = "www.google.com";
        System.arraycopy(hostname.getBytes(), 0, clientHello, offset, hostname.length());
        offset += hostname.length();

        // Fill length values
        int totalPayloadLen = offset;
        int recordLen = totalPayloadLen - 5;
        clientHello[recLenPos] = (byte) ((recordLen >> 8) & 0xFF);
        clientHello[recLenPos + 1] = (byte) (recordLen & 0xFF);

        int handLen = totalPayloadLen - 9;
        clientHello[handLenPos] = (byte) ((handLen >> 16) & 0xFF);
        clientHello[handLenPos + 1] = (byte) ((handLen >> 8) & 0xFF);
        clientHello[handLenPos + 2] = (byte) (handLen & 0xFF);

        int extLen = totalPayloadLen - extStart;
        clientHello[extLenPos] = (byte) ((extLen >> 8) & 0xFF);
        clientHello[extLenPos + 1] = (byte) (extLen & 0xFF);

        Optional<String> sni = SNIExtractor.extract(clientHello, 0, clientHello.length);
        assertTrue(sni.isPresent());
        assertEquals("www.google.com", sni.get());
    }
}
