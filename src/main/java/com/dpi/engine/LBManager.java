package com.dpi.engine;

import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;
import java.util.ArrayList;
import java.util.List;

/**
 * LBManager - Manages a pool of LoadBalancer threads and distributes incoming
 * packets to the correct LoadBalancer based on hash.
 */
public class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final int fpsPerLb;

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;

        // Create load balancers, each handling a subset of FPs
        for (int lbId = 0; lbId < numLbs; lbId++) {
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            int fpStart = lbId * fpsPerLb;

            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }

            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) {
            lb.start();
        }
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) {
            lb.stop();
        }
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        // First level of load balancing: select LB based on hash (avoiding negative hashes)
        int hash = tuple.hashCode();
        int lbIndex = (hash & Integer.MAX_VALUE) % lbs.size();
        return lbs.get(lbIndex);
    }

    public LoadBalancer getLB(int id) {
        return lbs.get(id);
    }

    public int getNumLBs() {
        return lbs.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats lbStats = lb.getStats();
            stats.totalReceived += lbStats.packetsReceived;
            stats.totalDispatched += lbStats.packetsDispatched;
        }
        return stats;
    }

    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }
}
