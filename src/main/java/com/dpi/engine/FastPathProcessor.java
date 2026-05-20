package com.dpi.engine;

import com.dpi.parser.*;
import com.dpi.tracking.ConnectionTracker;
import com.dpi.types.*;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * FastPathProcessor - Inspects packets, tracks connection states, and applies blocking rules.
 * Runs in its own processing thread.
 */
public class FastPathProcessor {
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;

    // Statistics
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId, 100000);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running) return;

        running = true;
        thread = new Thread(this::run, "FastPathProcessor-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;

        running = false;
        inputQueue.shutdown();

        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    private void run() {
        while (running) {
            // Get packet from input queue
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (!jobOpt.isPresent()) {
                // Periodically cleanup stale connections (timeout after 5 minutes)
                connTracker.cleanupStale(Duration.ofSeconds(300));
                continue;
            }

            PacketJob job = jobOpt.get();
            packetsProcessed.incrementAndGet();

            // Process the packet
            PacketAction action = processPacket(job);

            // Call output callback
            if (outputCallback != null) {
                outputCallback.handleOutput(job, action);
            }

            // Update stats
            if (action == PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        // Get or create connection
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            return PacketAction.FORWARD;
        }

        // Update connection stats
        connTracker.updateConnection(conn, job.data.length, true);

        // Update TCP state if protocol is TCP
        if (job.tuple.getProtocol() == 6) {
            updateTCPState(conn, job.tcpFlags);
        }

        // If connection is already blocked, drop immediately
        if (conn.getState() == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // If connection is not yet classified, try to inspect payload
        if (conn.getState() != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        // Check rules
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) {
            return;
        }

        // Try TLS SNI extraction first
        if (tryExtractSNI(job, conn)) {
            return;
        }

        // Try HTTP Host header extraction
        if (tryExtractHTTPHost(job, conn)) {
            return;
        }

        // Check for DNS query (port 53)
        if (job.tuple.getDstPort() == 53 || job.tuple.getSrcPort() == 53) {
            Optional<String> domain = DNSExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Basic port-based fallback
        if (job.tuple.getDstPort() == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.getDstPort() == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.getDstPort() != 443 && job.payloadLength < 50) {
            return false;
        }

        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) {
            return false;
        }

        // Try to extract SNI
        Optional<String> sni = SNIExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();

            AppType app = AppTypeDetector.sniToAppType(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }

        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.getDstPort() != 80) {
            return false;
        }

        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) {
            return false;
        }

        Optional<String> host = HTTPHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host.isPresent()) {
            AppType app = AppTypeDetector.sniToAppType(host.get());
            connTracker.classifyConnection(conn, app, host.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }

        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        long srcIp = job.tuple.getSrcIp();

        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
            srcIp,
            job.tuple.getDstPort(),
            conn.getAppType(),
            conn.getSni()
        );

        if (reason.isPresent()) {
            RuleManager.BlockReason r = reason.get();
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + r.type + " " + r.detail);

            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, byte tcpFlags) {
        final byte SYN = 0x02;
        final byte ACK = 0x10;
        final byte FIN = 0x01;
        final byte RST = 0x04;

        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) {
                conn.setSynAckSeen(true);
            } else {
                conn.setSynSeen(true);
            }
        }

        if (conn.isSynSeen() && conn.isSynAckSeen() && (tcpFlags & ACK) != 0) {
            if (conn.getState() == ConnectionState.NEW) {
                conn.setState(ConnectionState.ESTABLISHED);
            }
        }

        if ((tcpFlags & FIN) != 0) {
            conn.setFinSeen(true);
        }

        if ((tcpFlags & RST) != 0) {
            conn.setState(ConnectionState.CLOSED);
        }

        if (conn.isFinSeen() && (tcpFlags & ACK) != 0) {
            conn.setState(ConnectionState.CLOSED);
        }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running;
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packetsProcessed = packetsProcessed.get();
        stats.packetsForwarded = packetsForwarded.get();
        stats.packetsDropped = packetsDropped.get();
        stats.connectionsTracked = connTracker.getActiveCount();
        stats.sniExtractions = sniExtractions.get();
        stats.classificationHits = classificationHits.get();
        return stats;
    }

    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }
}
