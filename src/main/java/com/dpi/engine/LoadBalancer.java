package com.dpi.engine;

import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * LoadBalancer - Consistent hashing distributor of packets to FP queues.
 * Runs in its own processing thread.
 */
public class LoadBalancer {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    // Statistics
    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.fpQueues = new ArrayList<>(fpQueues);
        this.perFpCounts = new long[numFps];
    }

    public void start() {
        if (running) return;

        running = true;
        thread = new Thread(this::run, "LoadBalancer-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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
        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running) {
            // Get packet from input queue
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (!jobOpt.isPresent()) {
                continue; // Timeout or shutdown
            }

            packetsReceived.incrementAndGet();

            // Select target FP based on five-tuple hash
            int fpIndex = selectFP(jobOpt.get().tuple);

            // Push to selected FP's queue
            fpQueues.get(fpIndex).push(jobOpt.get());

            packetsDispatched.incrementAndGet();
            perFpCounts[fpIndex]++;
        }
    }

    public int selectFP(FiveTuple tuple) {
        // Hash the five-tuple and map to one of our FPs (avoiding negative hashes)
        int hash = tuple.hashCode();
        return (hash & Integer.MAX_VALUE) % numFps;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public int getId() {
        return lbId;
    }

    public boolean isRunning() {
        return running;
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        
        stats.perFpPackets = new ArrayList<>();
        for (long count : perFpCounts) {
            stats.perFpPackets.add(count);
        }
        return stats;
    }

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public List<Long> perFpPackets;
    }
}
