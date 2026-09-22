# Arc-Scan

> **Network Discovery & Security Auditor**

Arc-Scan is a terminal-first network scanner built from scratch in Python. It discovers reachable hosts, scans TCP services concurrently, identifies services from network evidence, performs basic TLS and security checks, and produces structured reports.

The project is designed around a simple idea:

```text
Discover → Identify → Analyze → Audit → Report
```

---

## Why Arc-Scan?

A basic port scanner answers:

> "Is this port open?"

Arc-Scan goes one step further:

```text
Host
  ↓
Open Port
  ↓
Service
  ↓
Banner / TLS Evidence
  ↓
OS / Device Hypothesis
  ↓
Security Finding
```

The goal is to keep the terminal output simple while keeping the internal scan pipeline structured enough to grow into a deeper network intelligence tool.

---

## Architecture

```text
                     ARC-SCAN
                        |
                        v
                  Target Manager
                        |
                        v
                 Host Discovery
                        |
                        v
                 TCP Scan Engine
                        |
                        v
              Service / Banner Detection
                        |
                +-------+-------+
                |               |
                v               v
          TLS Analysis     OS / Device
                           Inference
                |               |
                +-------+-------+
                        |
                        v
                  Security Audit
                        |
                        v
                 Structured Results
                        |
             +----------+----------+
             |          |          |
             v          v          v
         Terminal      JSON     CSV / XML
```

---

## Current Features

- IPv4 target and CIDR handling
- Basic IPv6-aware target parsing
- ICMP host discovery
- TCP fallback host discovery
- Concurrent TCP port scanning
- Quick, Normal, Deep, and Audit profiles
- Banner grabbing
- Basic service identification
- Basic version extraction
- TLS detection
- Basic OS inference
- Basic device classification
- Cleartext service checks
- Anonymous FTP detection
- Structured findings and evidence
- Interactive terminal mode
- JSON, CSV, and XML export
- Platform and privilege information
- Self-test entry point

> **Note:** The current implementation is intentionally focused on TCP scanning and basic service/security analysis. Advanced capabilities such as UDP scanning, deep fingerprinting, adaptive scanning, historical comparison, and AI assistance are planned extensions, not current claims.

---

## Quick Start

### Run a scan

```bash
python arc_scan.py 192.168.1.1
```

### Scan a subnet

```bash
python arc_scan.py 192.168.1.0/24
```

### Use a profile

```bash
python arc_scan.py 192.168.1.0/24 --profile deep
```

### Specify ports

```bash
python arc_scan.py 192.168.1.10 --ports 22,80,443
```

### Run security checks

```bash
python arc_scan.py 192.168.1.10 --audit
```

### Export results

```bash
python arc_scan.py 192.168.1.0/24 --json scan.json
```

Also supported:

```text
--csv
--xml
```

### Check platform capabilities

```bash
python arc_scan.py --platform-info
```

### Run self-test

```bash
python arc_scan.py --self-test
```

---

## Example Output

```text
HOST 192.168.1.10

Status      UP
Device      Server
OS          Linux
Confidence  75%

OPEN SERVICES

PORT       SERVICE       VERSION
22/tcp     SSH           OpenSSH
80/tcp     HTTP          nginx
443/tcp    HTTPS         ...

SECURITY

[!] 1 finding

SUMMARY

Hosts up:   1
Open ports: 3
Findings:   1
Duration:   1.42s
```

The default report intentionally avoids printing every closed port and low-level network event.

---

## Technical Highlights

### Concurrent scanning

Built around `asyncio` with bounded concurrency to improve scan performance without creating uncontrolled workloads.

### Structured result model

Scan data is represented through explicit objects for:

```text
Host
Service
Finding
Evidence
ScanResult
```

This keeps scanning, analysis, and output separate.

### Evidence-based identification

Service and fingerprinting logic uses observations such as banners, open ports, and TLS responses. Unknown information remains unknown instead of being invented.

### Cross-platform awareness

The application detects platform, Python version, IPv6 availability, and privilege state before scanning.

### Multiple output formats

The same result model can be rendered for humans or exported for further processing.

---

## Security Scope

Arc-Scan is intended for systems and networks that the operator owns or is authorized to assess.

The current project does **not** implement:

- password cracking
- credential brute forcing
- exploitation
- malware
- persistence
- remote command execution
- destructive testing
- evasion mechanisms

Its security checks are designed around safe, non-destructive observation.

---

## Roadmap

The architecture is intentionally prepared for:

```text
Current
  ↓
UDP Scanning
  ↓
Deeper Protocol Fingerprinting
  ↓
Stronger OS / Device Fingerprinting
  ↓
Advanced TLS Auditing
  ↓
Evidence Correlation
  ↓
Adaptive Scanning
  ↓
Historical Change Detection
  ↓
Optional AI-Assisted Analysis
  ↓
Distributed Scanning
```

These are future capabilities and are kept separate from the current implementation.

---

## Project Structure

The current project is intentionally compact:

```text
Arc-Scan/
└── arc_scan.py
```

Although it is a single file, the code is organized around logical components for:

- configuration
- target parsing
- discovery
- scanning
- protocol helpers
- fingerprinting
- auditing
- result modeling
- output
- CLI

This keeps the initial project easy to run while leaving a path toward future modularization.

---

## Technology

- **Python**
- **asyncio**
- **socket**
- **ssl**
- **argparse**
- **dataclasses**
- **JSON / CSV / XML**

The current implementation primarily uses the Python standard library.

---

## Project Status

**Working cybersecurity portfolio project.**

The current version provides an end-to-end pipeline for:

**host discovery → TCP scanning → service identification → basic analysis → security auditing → reporting**

The architecture is designed to support deeper network intelligence as the project evolves.

---

## License

Add the project's chosen license here before publishing.

---

**Arc-Scan**  
*Network Discovery & Security Auditor*
