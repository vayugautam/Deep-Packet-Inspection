package com.dpi;

import com.dpi.engine.DPIEngine;
import com.dpi.types.AppType;
import java.util.ArrayList;
import java.util.List;

/**
 * Main entry point for DPI Packet Analyzer
 */
public class PacketAnalyzerMain {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        // Parse options
        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        String rulesFile = null;

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--rules") && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                try {
                    config.numLoadBalancers = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid number of LBs: " + args[i]);
                }
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                try {
                    config.fpsPerLb = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid number of FPs: " + args[i]);
                }
            } else if (arg.equals("--verbose")) {
                config.verbose = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                printUsage();
                System.exit(0);
            }
        }

        if (rulesFile != null) {
            config.rulesFile = rulesFile;
        }

        try {
            // Create DPI engine
            DPIEngine engine = new DPIEngine(config);

            // Initialize
            if (!engine.initialize()) {
                System.err.println("Failed to initialize DPI engine");
                System.exit(1);
            }

            // Apply command-line blocking rules
            for (String ip : blockIps) {
                engine.blockIP(ip);
            }

            for (String app : blockApps) {
                engine.blockApp(app);
            }

            for (String domain : blockDomains) {
                engine.blockDomain(domain);
            }

            // Process the file
            if (!engine.processFile(inputFile, outputFile)) {
                System.err.println("Failed to process file");
                System.exit(1);
            }

            System.out.println("\nProcessing complete!");
            System.out.println("Output saved to: " + outputFile);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Usage: java -jar packet-analyzer.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  input.pcap     Input PCAP file (captured user traffic)");
        System.out.println("  output.pcap    Output PCAP file (filtered traffic to internet)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block packets from source IP");
        System.out.println("  --block-app <app>      Block application (e.g., YouTube, Facebook)");
        System.out.println("  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)");
        System.out.println("  --rules <file>         Load blocking rules from file");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)");
        System.out.println("  --verbose              Enable verbose output");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap filtered.pcap");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app YouTube");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com");
        System.out.println("  java -jar packet-analyzer.jar capture.pcap filtered.pcap --rules blocking_rules.txt");
        System.out.println();
        System.out.println("Supported Apps for Blocking:");
        System.out.println("  Google, YouTube, Facebook, Instagram, Twitter, Netflix, Amazon,");
        System.out.println("  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub");
    }
}
