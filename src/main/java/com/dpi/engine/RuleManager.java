package com.dpi.engine;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RuleManager - Manages blocking and filtering rules
 */
public class RuleManager {
    private final Set<Long> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final Set<Integer> blockedPorts = ConcurrentHashMap.newKeySet();
    private final Map<String, Boolean> blockedApps = new ConcurrentHashMap<>();

    /**
     * Block a source IP address
     */
    public void blockIP(String ip) {
        long ipLong = FiveTuple.parseIp(ip);
        blockIP(ipLong);
    }

    public void blockIP(long ip) {
        blockedIps.add(ip);
        System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
    }

    /**
     * Unblock an IP
     */
    public void unblockIP(String ip) {
        long ipLong = FiveTuple.parseIp(ip);
        blockedIps.remove(ipLong);
    }

    public void unblockIP(long ip) {
        blockedIps.remove(ip);
        System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
    }

    /**
     * Check if IP is blocked
     */
    public boolean isIPBlocked(long ip) {
        return blockedIps.contains(ip);
    }

    /**
     * Get blocked IPs
     */
    public List<String> getBlockedIPs() {
        List<String> result = new ArrayList<>();
        for (long ip : blockedIps) {
            result.add(FiveTuple.ipToString(ip));
        }
        Collections.sort(result);
        return result;
    }

    /**
     * Block an application type
     */
    public void blockApp(AppType app) {
        blockedApps.put(app.getDisplayName(), true);
        System.out.println("[RuleManager] Blocked app: " + app.getDisplayName());
    }

    /**
     * Unblock an application
     */
    public void unblockApp(AppType app) {
        blockedApps.remove(app.getDisplayName());
        System.out.println("[RuleManager] Unblocked app: " + app.getDisplayName());
    }

    /**
     * Check if app is blocked
     */
    public boolean isAppBlocked(AppType app) {
        return blockedApps.containsKey(app.getDisplayName());
    }

    /**
     * Get blocked apps
     */
    public List<String> getBlockedApps() {
        return new ArrayList<>(blockedApps.keySet());
    }

    /**
     * Block a domain
     */
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    /**
     * Unblock a domain
     */
    public void unblockDomain(String domain) {
        blockedDomains.remove(domain.toLowerCase());
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    /**
     * Check if domain is blocked
     */
    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }

        String lower = domain.toLowerCase();
        
        for (String blockedPattern : blockedDomains) {
            if (blockedPattern.startsWith("*.")) {
                // Wildcard matching (matches subdomains and bare domain, e.g., *.example.com matches sub.example.com and example.com)
                String suffix = blockedPattern.substring(1); // Remove *
                if (lower.endsWith(suffix)) {
                    return true;
                }
                String bare = blockedPattern.substring(2); // Remove *.
                if (lower.equals(bare)) {
                    return true;
                }
            } else if (lower.equals(blockedPattern)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Get blocked domains
     */
    public List<String> getBlockedDomains() {
        return new ArrayList<>(blockedDomains);
    }

    /**
     * Block a destination port
     */
    public void blockPort(int port) {
        blockedPorts.add(port);
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    /**
     * Unblock a port
     */
    public void unblockPort(int port) {
        blockedPorts.remove(port);
    }

    /**
     * Check if port is blocked
     */
    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port);
    }

    /**
     * Combined check - should block this connection?
     */
    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        // Check IP blocking (most specific)
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp)));
        }

        // Check port blocking
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        }

        // Check app blocking
        if (app != AppType.UNKNOWN && isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.getDisplayName()));
        }

        // Check domain blocking
        if (isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }

        return Optional.empty();
    }

    /**
     * Save rules to file
     */
    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(filename)))) {
            // Save blocked IPs
            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) {
                writer.println(ip);
            }
            
            // Save blocked apps
            writer.println("\n[BLOCKED_APPS]");
            for (String app : getBlockedApps()) {
                writer.println(app);
            }
            
            // Save blocked domains
            writer.println("\n[BLOCKED_DOMAINS]");
            for (String domain : getBlockedDomains()) {
                writer.println(domain);
            }
            
            // Save blocked ports
            writer.println("\n[BLOCKED_PORTS]");
            for (int port : blockedPorts) {
                writer.println(port);
            }
            
            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error saving rules: " + e.getMessage());
            return false;
        }
    }

    /**
     * Load rules from file
     */
    public boolean loadRules(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";
            
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                
                if (line.startsWith("[") && line.endsWith("]")) {
                    currentSection = line;
                    continue;
                }
                
                switch (currentSection) {
                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;
                    case "[BLOCKED_APPS]":
                        // Convert string name back to AppType
                        for (AppType type : AppType.values()) {
                            if (type.getDisplayName().equalsIgnoreCase(line)) {
                                blockApp(type);
                                break;
                            }
                        }
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        try {
                            blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException e) {
                            System.err.println("[RuleManager] Invalid port rule: " + line);
                        }
                        break;
                }
            }
            
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error loading rules from " + filename + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Clear all rules
     */
    public void clearAll() {
        blockedIps.clear();
        blockedDomains.clear();
        blockedPorts.clear();
        blockedApps.clear();
        System.out.println("[RuleManager] All rules cleared");
    }

    /**
     * Get statistics
     */
    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        stats.blockedIps = blockedIps.size();
        stats.blockedApps = blockedApps.size();
        stats.blockedDomains = blockedDomains.size();
        stats.blockedPorts = blockedPorts.size();
        return stats;
    }

    /**
     * Rule statistics representation
     */
    public static class RuleStats {
        public long blockedIps;
        public long blockedApps;
        public long blockedDomains;
        public long blockedPorts;
    }

    /**
     * Block reason representation
     */
    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }

        @Override
        public String toString() {
            return String.format("BlockReason{type=%s, detail=%s}", type, detail);
        }
    }
}
