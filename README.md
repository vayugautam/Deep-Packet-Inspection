# DPI Packet Analyzer - Java Version

This is a complete, production-ready Java port of the C++ DPI (Deep Packet Inspection) engine. The functionality is **100% identical** to the original C++ version, featuring the exact same multi-threaded pipeline architecture, consistent hashing load balancers, fast-path processors, and application extraction engines.

## Overview

The DPI Engine reads PCAP packet capture files, inspects packet contents, detects applications (via SNI and HTTP host extraction), and blocks traffic in real-time based on configurable rules.

### Features

- **PCAP Parsing**: Supports reading standard libpcap format files with native or swapped endianness.
- **Packet Inspection**: Inspects Ethernet, IPv4, TCP, and UDP headers.
- **SNI Extraction**: Extracts Server Name Indication (SNI) from TLS (HTTPS) Client Hellos and QUIC initial connection packets.
- **HTTP Host Extraction**: Extracts unencrypted Host headers from HTTP requests.
- **DNS Query Extraction**: Identifies and extracts domain names queried via DNS.
- **Multi-Threaded Architecture**: Uses consistent hashing to load-balance traffic stickily across a pool of worker threads.
- **Rule-Based Filtering**: Real-time traffic blocking by Source IP, Application type, Destination Domain (supports wildcards like `*.domain.com`), and TCP/UDP ports.
- **Statistics Reporting**: Generates detailed statistical reports on packet counts, bytes, actions, and application classifications.

---

## Architecture

The Java engine implements the exact producer-consumer multi-threaded pipeline of the C++ engine:

```
                  ┌──────────────┐
                  │  PCAP Reader │
                  └──────┬───────┘
                         │ hash(5-tuple) % num_lbs
                         ▼
                  ┌──────┴───────┐
                  │ Load Balancer│  (N threads)
                  └──────┬───────┘
                         │ hash(5-tuple) % fps_per_lb
                         ▼
                  ┌──────┴───────┐
                  │  Fast Path   │  (N * M threads)
                  │  Processors  │  (Payload extraction, blocking rules)
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────┴───────┐
                  │ Output Queue │  (ThreadSafeQueue)
                  └──────┬───────┘
                         ▼
                  ┌──────┴───────┐
                  │ Output Writer│  (Writes to forwarded PCAP file)
                  └──────────────┘
```

### Component Mapping (C++ → Java)

| C++ Component | Java Component | Description |
|:---|:---|:---|
| `types.h` / `types.cpp` | `com.dpi.types.*` | Core models: `FiveTuple`, `Connection`, `AppType`, `PacketJob`, `DPIStats` |
| `pcap_reader.cpp` | `com.dpi.parser.PcapReader` | PCAP stream input handling with endianness checking |
| `packet_parser.cpp` | `com.dpi.parser.PacketParser` | Layer 2/3/4 packet parser and validator |
| `sni_extractor.cpp` | `com.dpi.parser.SNIExtractor` | TLS SNI hostname parser |
| `http_host_extractor.cpp` | `com.dpi.parser.HTTPHostExtractor` | Dotted HTTP request Host header parser |
| `dns_extractor.cpp` | `com.dpi.parser.DNSExtractor` | DNS request query parser |
| `quic_sni_extractor.cpp`| `com.dpi.parser.QUICSNIExtractor` | QUIC SNI parser |
| `thread_safe_queue.h` | `com.dpi.engine.ThreadSafeQueue` | Lock-bounded thread-safe blocking queue |
| `load_balancer.cpp` | `com.dpi.engine.LoadBalancer` / `LBManager` | Consistent-hashing load distribution |
| `fast_path.cpp` | `com.dpi.engine.FastPathProcessor` / `FPManager` | State-tracking, payload inspection, and rule matching |
| `connection_tracker.cpp`| `com.dpi.tracking.ConnectionTracker` | Flow state management |
| `rule_manager.cpp` | `com.dpi.engine.RuleManager` | Rule parsing, compilation, serialization, and wildcard matching |
| `dpi_engine.cpp` | `com.dpi.engine.DPIEngine` | Orchestrator and output writer |
| `main_dpi.cpp` | `com.dpi.PacketAnalyzerMain` | CLI Entry point |

---

## Getting Started

### Prerequisites

- **Java 11** or higher
- **Maven 3.6** or higher

### Build

Compile and package the project into an executable JAR:

```bash
mvn clean package
```

This generates:
- `target/packet-analyzer-1.0.0.jar` (standard jar)
- `target/packet-analyzer-1.0.0-shaded.jar` (self-contained executable fat jar containing dependencies)

---

## Running the Engine

### CLI Usage

```bash
java -jar target/packet-analyzer-1.0.0-shaded.jar <input.pcap> <output.pcap> [options]
```

### Options

| Option | Argument | Description |
|:---|:---|:---|
| `--block-ip` | `<ip>` | Block packets originating from source IP (e.g. `192.168.1.50`) |
| `--block-app` | `<app>` | Block packets matching application (e.g. `YouTube`, `Facebook`, `Netflix`) |
| `--block-domain`| `<domain>`| Block packets matching destination domain (supports wildcards like `*.tiktok.com`) |
| `--rules` | `<file>` | Load blocking rules from a file |
| `--lbs` | `<n>` | Number of load balancer threads (default: 2) |
| `--fps` | `<n>` | Number of Fast Path worker threads per Load Balancer (default: 2) |
| `--verbose` | | Enable verbose logging |

### Rules File Format

You can load blocking rules from a text file (e.g. `rules.txt`):

```text
# Block a source IP address
BLOCK_IP 10.0.0.45

# Block application categories (Case-insensitive)
BLOCK_APP YOUTUBE
BLOCK_APP FACEBOOK

# Block domains (Supports subdomains via wildcards)
BLOCK_DOMAIN *.tiktok.com
BLOCK_DOMAIN suspicious-website.net

# Block ports
BLOCK_PORT 8080
```

Load the rules using:
```bash
java -jar target/packet-analyzer-1.0.0-shaded.jar test_dpi.pcap output.pcap --rules rules.txt
```

---

## Test Suite

The project includes an automated JUnit test suite validating:
1. **RuleManager**: Wildcard domain checks, IP/App/Port blocking, rules loading/saving serialization.
2. **ProtocolExtractors**: Correct identification and hostname extraction for DNS queries, HTTP Host headers, and TLS/QUIC SNI records.
3. **ThreadSafeQueue**: Capacity limits, thread safety, and thread shutdown handling.

To run the unit tests:

```bash
mvn test
```

---

## Verification against sample PCAPs

To generate sample traffic and run the Java engine for verification:

1. Generate sample PCAP (requires Python with `scapy` installed):
   ```bash
   python generate_test_pcap.py
   ```
2. Run the Java DPI Packet Analyzer to inspect and block traffic:
   ```bash
   java -jar target/packet-analyzer-1.0.0-shaded.jar test_dpi.pcap output.pcap --block-app YouTube --block-domain *.tiktok.com
   ```
3. The engine will print a comprehensive status report on stdout and write the forwarded traffic to `output.pcap`.
