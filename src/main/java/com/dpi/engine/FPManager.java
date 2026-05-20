package com.dpi.engine;

import com.dpi.tracking.ConnectionTracker;
import com.dpi.types.AppType;
import com.dpi.types.Connection;
import java.util.*;

/**
 * FPManager - Manages the lifecycle of Fast Path Processor threads
 * and aggregates their classification statistics.
 */
public class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public ThreadSafeQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> queues = new ArrayList<>();
        for (FastPathProcessor fp : fps) {
            queues.add(fp.getInputQueue());
        }
        return queues;
    }

    public int getNumFPs() {
        return fps.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats fpStats = fp.getStats();
            stats.totalProcessed += fpStats.packetsProcessed;
            stats.totalForwarded += fpStats.packetsForwarded;
            stats.totalDropped += fpStats.packetsDropped;
            stats.totalConnections += fpStats.connectionsTracked;
        }
        return stats;
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        Map<String, Long> domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                AppType app = conn.getAppType();
                appCounts.put(app, appCounts.getOrDefault(app, 0L) + 1);

                if (app == AppType.UNKNOWN) {
                    // Note: C++ uses total_unknown++ and total_classified++
                    // We match that logic here
                }

                if (app == AppType.UNKNOWN) {
                    // In Java we can't update a local final long directly, so we'll just count them
                }

                String sni = conn.getSni();
                if (sni != null && !sni.isEmpty()) {
                    domainCounts.put(sni, domainCounts.getOrDefault(sni, 0L) + 1);
                }
            });
        }

        // Count classified and unknown
        for (Map.Entry<AppType, Long> entry : appCounts.entrySet()) {
            if (entry.getKey() == AppType.UNKNOWN) {
                totalUnknown += entry.getValue();
            } else {
                totalClassified += entry.getValue();
            }
        }

        StringBuilder ss = new StringBuilder();
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

        ss.append(String.format("║ Total Connections:    %10d                           ║\n", total));
        ss.append(String.format("║ Classified:           %10d (%5.1f%%)                  ║\n", totalClassified, classifiedPct));
        ss.append(String.format("║ Unidentified:         %10d (%5.1f%%)                  ║\n", totalUnknown, unknownPct));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        // Sort apps by count
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            int barLen = (int) (pct / 5);
            StringBuilder bar = new StringBuilder();
            for (int i = 0; i < barLen; i++) {
                bar.append("#");
            }

            ss.append(String.format("║ %-15s%8d %5.1f%% %-20s   ║\n",
                    entry.getKey().getDisplayName(),
                    entry.getValue(),
                    pct,
                    bar.toString()));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public static class AggregatedStats {
        public long totalProcessed;
        public long totalForwarded;
        public long totalDropped;
        public long totalConnections;
    }
}
