package com.dpi.tracking;

import com.dpi.types.*;
import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/**
 * ConnectionTracker - Tracks network connections/flows
 */
public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    
    private final Map<FiveTuple, Connection> connections;
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        this.connections = new ConcurrentHashMap<>();
    }

    /**
     * Get or create a connection for the given tuple
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = getConnection(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        Connection newConn = new Connection(tuple);
        Connection existing = connections.putIfAbsent(tuple, newConn);
        if (existing == null) {
            totalSeen++;
            return newConn;
        }
        return existing;
    }

    /**
     * Get existing connection
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        
        // Try reverse tuple (for bidirectional matching)
        return connections.get(tuple.reverse());
    }

    /**
     * Update connection statistics
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        
        if (isOutbound) {
            conn.updateOutbound(packetSize);
        } else {
            conn.updateInbound(packetSize);
        }
    }

    /**
     * Classify a connection
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        
        if (conn.getState() != ConnectionState.CLASSIFIED) {
            conn.setAppType(app);
            conn.setSni(sni);
            conn.setState(ConnectionState.CLASSIFIED);
            classifiedCount++;
        }
    }

    /**
     * Block a connection
     */
    public void blockConnection(Connection conn) {
        if (conn == null) return;
        
        conn.setState(ConnectionState.BLOCKED);
        conn.setAction(PacketAction.DROP);
        blockedCount++;
    }

    /**
     * Close a connection
     */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.setState(ConnectionState.CLOSED);
        }
    }

    /**
     * Clean up stale connections
     */
    public int cleanupStale(Duration timeout) {
        Instant now = Instant.now();
        int removed = 0;
        
        Iterator<Map.Entry<FiveTuple, Connection>> iter = connections.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = iter.next();
            Connection conn = entry.getValue();
            
            Duration age = Duration.between(conn.getLastSeen(), now);
            if (age.compareTo(timeout) > 0 || conn.getState() == ConnectionState.CLOSED) {
                iter.remove();
                removed++;
            }
        }
        
        return removed;
    }

    /**
     * Get all connections
     */
    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    /**
     * Get active connection count
     */
    public int getActiveCount() {
        return connections.size();
    }

    /**
     * Get tracker statistics
     */
    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    /**
     * Clear all connections
     */
    public void clear() {
        connections.clear();
    }

    /**
     * Iterate over all connections
     */
    public void forEach(java.util.function.Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        
        FiveTuple oldest = null;
        Instant oldestTime = Instant.now();
        
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().getLastSeen().isBefore(oldestTime)) {
                oldest = entry.getKey();
                oldestTime = entry.getValue().getLastSeen();
            }
        }
        
        if (oldest != null) {
            connections.remove(oldest);
        }
    }

    /**
     * Tracker statistics
     */
    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;

        @Override
        public String toString() {
            return String.format("TrackerStats{active=%d, total_seen=%d, classified=%d, blocked=%d}",
                    activeConnections, totalConnectionsSeen, classifiedConnections, blockedConnections);
        }
    }
}
