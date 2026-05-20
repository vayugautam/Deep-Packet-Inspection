package com.dpi.tracking;

import com.dpi.types.AppType;
import com.dpi.types.Connection;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.StampedLock;

/**
 * GlobalConnectionTable - Aggregates stats from all FP trackers
 * and generates reports.
 */
public class GlobalConnectionTable {
    private final List<ConnectionTracker> trackers;
    private final StampedLock lock = new StampedLock();

    public GlobalConnectionTable(int numFps) {
        this.trackers = new ArrayList<>(Collections.nCopies(numFps, null));
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        long stamp = lock.writeLock();
        try {
            if (fpId < trackers.size()) {
                trackers.set(fpId, tracker);
            }
        } finally {
            lock.unlockWrite(stamp);
        }
    }

    public GlobalStats getGlobalStats() {
        long stamp = lock.readLock();
        try {
            GlobalStats stats = new GlobalStats();
            stats.totalActiveConnections = 0;
            stats.totalConnectionsSeen = 0;
            stats.appDistribution = new EnumMap<>(AppType.class);

            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats trackerStats = tracker.getStats();
                stats.totalActiveConnections += trackerStats.activeConnections;
                stats.totalConnectionsSeen += trackerStats.totalConnectionsSeen;

                // Collect app and domain distributions
                tracker.forEach(conn -> {
                    AppType app = conn.getAppType();
                    stats.appDistribution.put(app, stats.appDistribution.getOrDefault(app, 0L) + 1);

                    String sni = conn.getSni();
                    if (sni != null && !sni.isEmpty()) {
                        domainCounts.put(sni, domainCounts.getOrDefault(sni, 0L) + 1);
                    }
                });
            }

            // Get top domains
            List<Map.Entry<String, Long>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            stats.topDomains = new ArrayList<>();
            int count = Math.min(domainList.size(), 20);
            for (int i = 0; i < count; i++) {
                stats.topDomains.add(domainList.get(i));
            }

            return stats;
        } finally {
            lock.unlockRead(stamp);
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder ss = new StringBuilder();

        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append(String.format("║ Active Connections:     %10d                          ║\n", stats.totalActiveConnections));
        ss.append(String.format("║ Total Connections Seen: %10d                          ║\n", stats.totalConnectionsSeen));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║                    APPLICATION BREAKDOWN                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        // Calculate total for percentages
        long total = 0;
        for (long count : stats.appDistribution.values()) {
            total += count;
        }

        // Sort by count
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0;
            ss.append(String.format("║ %-20s%10d (%5.1f%%)           ║\n",
                    entry.getKey().getDisplayName(),
                    entry.getValue(),
                    pct));
        }

        if (!stats.topDomains.isEmpty()) {
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║                      TOP DOMAINS                             ║\n");
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");

            for (Map.Entry<String, Long> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                ss.append(String.format("║ %-40s%10d           ║\n", domain, entry.getValue()));
            }
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public static class GlobalStats {
        public long totalActiveConnections;
        public long totalConnectionsSeen;
        public Map<AppType, Long> appDistribution;
        public List<Map.Entry<String, Long>> topDomains;
    }
}
