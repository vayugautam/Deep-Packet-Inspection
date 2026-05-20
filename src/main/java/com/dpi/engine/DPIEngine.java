package com.dpi.engine;

import com.dpi.parser.*;
import com.dpi.tracking.GlobalConnectionTable;
import com.dpi.types.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DPIEngine - Orchestrates PCAP reader, Load Balancers, Fast Path Processors,
 * Rule matching, and PCAP writing in a multi-threaded pipeline.
 */
public class DPIEngine {
    private final Config config;
    
    // Shared components
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;
    
    // Thread pools
    private FPManager fpManager;
    private LBManager lbManager;
    
    // Output handling
    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10000);
    private Thread outputThread;
    private DataOutputStream outputFileStream;
    private final Object outputLock = new Object();
    
    // Statistics
    private final DPIStats stats = new DPIStats();
    
    // Control
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile boolean processingComplete = false;
    
    // Reader thread
    private Thread readerThread;

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile;
        public boolean verbose = false;
    }

    public DPIEngine(Config config) {
        this.config = config;
        
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.println(String.format("║   Load Balancers:    %3d                                     ║", config.numLoadBalancers));
        System.out.println(String.format("║   FPs per LB:        %3d                                     ║", config.fpsPerLb));
        System.out.println(String.format("║   Total FP threads:  %3d                                     ║", (config.numLoadBalancers * config.fpsPerLb)));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        // Create rule manager
        ruleManager = new RuleManager();
        
        // Load rules if specified
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }
        
        // Create output callback
        PacketOutputCallback outputCb = this::handleOutput;
        
        // Create FP manager (creates FP threads and their queues)
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, outputCb);
        
        // Create LB manager (creates LB threads, connects to FP queues)
        lbManager = new LBManager(
            config.numLoadBalancers,
            config.fpsPerLb,
            fpManager.getQueuePtrs()
        );
        
        // Create global connection table
        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }
        
        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.getAndSet(true)) return;
        
        processingComplete = false;
        
        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "OutputThread");
        outputThread.start();
        
        // Start FP threads
        fpManager.startAll();
        
        // Start LB threads
        lbManager.startAll();
        
        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.getAndSet(false)) return;
        
        // Stop LB threads first (they feed FPs)
        if (lbManager != null) {
            lbManager.stopAll();
        }
        
        // Stop FP threads
        if (fpManager != null) {
            fpManager.stopAll();
        }
        
        // Stop output thread
        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        // Wait for reader to finish
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        // Wait a bit for queues to drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Signal completion
        processingComplete = true;
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");
        
        // Initialize if not already done
        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }
        
        // Open output file
        try {
            outputFileStream = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file: " + e.getMessage());
            return false;
        }
        
        // Start processing threads
        start();
        
        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "ReaderThread");
        readerThread.start();
        
        // Wait for completion
        waitForCompletion();
        
        // Give some time for final packets to process
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Stop all threads
        stop();
        
        // Close output file
        try {
            if (outputFileStream != null) {
                outputFileStream.close();
            }
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error closing output file: " + e.getMessage());
        }
        
        // Print final reports
        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());
        
        return true;
    }

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader();
        
        try {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file: " + inputFile);
                return;
            }
            
            // Write PCAP header to output
            writeOutputHeader(reader.getGlobalHeader());
            
            RawPacket raw = new RawPacket(null, null);
            int packetId = 0;
            
            System.out.println("[Reader] Starting packet processing...");
            
            while (reader.readNextPacket(raw)) {
                // Parse the packet
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    continue; // Skip unparseable packets
                }
                
                // Only process IP packets with TCP/UDP
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                
                // Create packet job
                PacketJob job = createPacketJob(raw, parsed, packetId++);
                
                // Update global stats
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                
                if (parsed.hasTcp) {
                    stats.tcpPackets.incrementAndGet();
                } else if (parsed.hasUdp) {
                    stats.udpPackets.incrementAndGet();
                }
                
                // Send to appropriate LB based on hash
                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                lb.getInputQueue().push(job);
            }
            
            System.out.println("[Reader] Finished reading " + packetId + " packets");
            reader.close();
        } catch (IOException e) {
            System.err.println("[Reader] IOException while reading: " + e.getMessage());
        }
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSeconds;
        job.tsUsec = raw.header.tsMicroseconds;
        
        // Parse IPs to long representation
        long srcIp = FiveTuple.parseIp(parsed.srcIp);
        long destIp = FiveTuple.parseIp(parsed.destIp);
        
        job.tuple = new FiveTuple(srcIp, destIp, parsed.srcPort, parsed.destPort, (byte) parsed.protocol);
        job.tcpFlags = (byte) parsed.tcpFlags;
        job.data = raw.data;
        
        // Calculate offsets
        job.ethOffset = 0;
        job.ipOffset = 14; // Ethernet header is 14 bytes
        
        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;
            
            // Transport header length
            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8; // UDP header is 8 bytes
            }
            
            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }
        
        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            Optional<PacketJob> jobOpt = outputQueue.popWithTimeout(100);
            
            if (jobOpt.isPresent()) {
                writeOutputPacket(jobOpt.get());
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    private boolean writeOutputHeader(PcapGlobalHeader header) {
        synchronized (outputLock) {
            if (outputFileStream == null) return false;
            
            try {
                // Output is always written in Little Endian format to be consistent with C++ standard output
                ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt((int) header.magicNumber);
                bb.putShort((short) header.versionMajor);
                bb.putShort((short) header.versionMinor);
                bb.putInt(header.timezone);
                bb.putInt(header.sigfigs);
                bb.putInt((int) header.snaplen);
                bb.putInt((int) header.network);
                
                outputFileStream.write(bb.array());
                outputFileStream.flush();
                return true;
            } catch (IOException e) {
                System.err.println("[DPIEngine] Error writing output header: " + e.getMessage());
                return false;
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputLock) {
            if (outputFileStream == null) return;
            
            try {
                ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt((int) job.tsSec);
                bb.putInt((int) job.tsUsec);
                bb.putInt(job.data.length);
                bb.putInt(job.data.length);
                
                outputFileStream.write(bb.array());
                outputFileStream.write(job.data);
            } catch (IOException e) {
                System.err.println("[DPIEngine] Error writing output packet: " + e.getMessage());
            }
        }
    }

    // ========== Rule Management API ==========
    
    public void blockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.blockIP(ip);
        }
    }
    
    public void unblockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.unblockIP(ip);
        }
    }
    
    public void blockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.blockApp(app);
        }
    }
    
    public void blockApp(String appName) {
        for (AppType type : AppType.values()) {
            if (type.getDisplayName().equalsIgnoreCase(appName)) {
                blockApp(type);
                return;
            }
        }
        System.err.println("[DPIEngine] Unknown app: " + appName);
    }
    
    public void unblockApp(AppType app) {
        if (ruleManager != null) {
            ruleManager.unblockApp(app);
        }
    }
    
    public void unblockApp(String appName) {
        for (AppType type : AppType.values()) {
            if (type.getDisplayName().equalsIgnoreCase(appName)) {
                unblockApp(type);
                return;
            }
        }
    }
    
    public void blockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.blockDomain(domain);
        }
    }
    
    public void unblockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.unblockDomain(domain);
        }
    }
    
    public boolean loadRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.loadRules(filename);
        }
        return false;
    }
    
    public boolean saveRules(String filename) {
        if (ruleManager != null) {
            return ruleManager.saveRules(filename);
        }
        return false;
    }

    // ========== Reporting ==========

    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        
        ss.append("║ PACKET STATISTICS                                             ║\n");
        ss.append(String.format("║   Total Packets:      %12d                        ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                        ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                        ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                        ║\n", stats.udpPackets.get()));
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                          ║\n");
        ss.append(String.format("║   Forwarded:          %12d                        ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                        ║\n", stats.droppedPackets.get()));
        
        long totalPkts = stats.totalPackets.get();
        if (totalPkts > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / totalPkts;
            ss.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n", dropRate));
        }
        
        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            ss.append(String.format("║   LB Received:        %12d                        ║\n", lbStats.totalReceived));
            ss.append(String.format("║   LB Dispatched:      %12d                        ║\n", lbStats.totalDispatched));
        }
        
        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ FAST PATH STATISTICS                                          ║\n");
            ss.append(String.format("║   FP Processed:       %12d                        ║\n", fpStats.totalProcessed));
            ss.append(String.format("║   FP Forwarded:       %12d                        ║\n", fpStats.totalForwarded));
            ss.append(String.format("║   FP Dropped:         %12d                        ║\n", fpStats.totalDropped));
            ss.append(String.format("║   Active Connections: %12d                        ║\n", fpStats.totalConnections));
        }
        
        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                                ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                        ║\n", ruleStats.blockedIps));
            ss.append(String.format("║   Blocked Apps:       %12d                        ║\n", ruleStats.blockedApps));
            ss.append(String.format("║   Blocked Domains:    %12d                        ║\n", ruleStats.blockedDomains));
            ss.append(String.format("║   Blocked Ports:      %12d                        ║\n", ruleStats.blockedPorts));
        }
        
        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        
        return ss.toString();
    }

    public String generateClassificationReport() {
        if (fpManager != null) {
            return fpManager.generateClassificationReport();
        }
        return "";
    }

    public DPIStats getStats() {
        return stats;
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public boolean isRunning() {
        return running.get();
    }
}
