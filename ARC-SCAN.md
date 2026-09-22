# Arc-Scan

## Network Discovery & Security Auditor

Arc-Scan is a terminal-first network discovery and security auditing tool built from scratch in Python.

Its current implementation focuses on discovering reachable hosts, scanning TCP ports concurrently, identifying services from banners and known-port context, performing basic TLS and security checks, inferring OS/device types heuristically, and exporting structured scan results.

---

## Overview

### Core workflow

```text
Target
  |
  v
Target Parsing
  |
  v
Host Discovery
  |
  v
TCP Port Scanning
  |
  v
Banner Grabbing
  |
  v
Service Identification
  |
  v
TLS Detection
  |
  v
OS / Device Inference
  |
  v
Security Audit
  |
  v
Structured ScanResult
  |
  +-------> Terminal Report
  +-------> JSON
  +-------> CSV
  +-------> XML
```

---

## Architecture

Arc-Scan is currently implemented in a single Python file, `arc_scan.py`, but its responsibilities are separated into logical components.

```text
                    +----------------------+
                    |       CLI / REPL     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |  Argument / Profile  |
                    |      Resolution      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |    Target Manager    |
                    | IP / CIDR / Hostname |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |   ArcScanner Core    |
                    +----------+-----------+
                               |
               +---------------+----------------+
               |                                |
               v                                v
      +----------------+              +----------------+
      | Host Discovery |              | Port Selection |
      | ICMP + TCP     |              | Profile/Custom |
      +-------+--------+              +--------+-------+
              |                                |
              +---------------+----------------+
                              |
                              v
                    +----------------------+
                    | TCP Scan Engine      |
                    | asyncio + semaphore  |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Service Detection    |
                    | banner + port hints  |
                    +----------+-----------+
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
        +----------------+          +----------------+
        | TLS Detection  |          | Host Inference |
        | SSL handshake  |          | OS / Device    |
        +----------------+          +----------------+
                 |                           |
                 +-------------+-------------+
                               |
                               v
                    +----------------------+
                    | Security Auditor     |
                    | cleartext + FTP      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Structured Data      |
                    | Host / Service /     |
                    | Finding / Evidence   |
                    +----------+-----------+
                               |
                 +-------------+-------------+
                 |             |             |
                 v             v             v
             Terminal        JSON        CSV / XML
```

---

## Main Components

### CLI and Interactive Mode

Arc-Scan supports two entry paths:

```text
CLI:
python arc_scan.py <target>

Interactive:
python arc_scan.py
```

The interactive mode accepts target and flag-style commands through the same argument parser used by the CLI.

### Scan Profiles

The current built-in profiles are:

| Profile | Purpose | Default Ports | Timeout | Concurrency |
|---|---|---|---:|---:|
| `quick` | Fast common-port scan | Common service ports | 1.0s | 200 |
| `normal` | General-purpose scan | 1-1024 plus selected ports | 2.0s | 100 |
| `deep` | Large TCP scan | 1-65535 | 3.0s | 50 |
| `audit` | Common service exposure review | Common service ports | 2.0s | 100 |

Custom port, timeout, and concurrency settings can override profile values.

---

## Target Handling

Arc-Scan accepts:

- single IP addresses
- CIDR networks
- IPv4 ranges
- hostnames resolvable through the system resolver

Targets are normalized, expanded, and deduplicated before scanning.

The current implementation also applies a safeguard against expanding more than 65,536 targets in one scan.

---

## Host Discovery

The current discovery process uses two stages.

### 1. ICMP discovery

Arc-Scan invokes the platform's `ping` command.

```text
Target
  |
  v
ICMP / ping
  |
  +--> response -> host considered reachable
  |
  +--> no response
             |
             v
        TCP fallback
```

### 2. TCP fallback

If ICMP does not confirm the host, Arc-Scan checks a small set of common TCP ports:

```text
80
443
22
445
3389
8080
```

A successful connection to one of these ports is treated as evidence that the host is reachable.

---

## Port Scanning

The current scanner implements TCP scanning.

Each connection attempt is classified as:

```text
OPEN
CLOSED
FILTERED
UNKNOWN
```

The scanner uses `asyncio` and a semaphore to bound concurrency.

### TCP flow

```text
TCP connection attempt
        |
        +--> connected       -> OPEN
        |
        +--> timeout         -> FILTERED
        |
        +--> refused/error   -> CLOSED
        |
        +--> other error     -> UNKNOWN
```

UDP scanning is not currently implemented even though UDP is part of the longer-term Arc-Scan design.

---

## Service Detection

When an open TCP port is found, Arc-Scan attempts to collect an application banner.

The current process is:

```text
Open Port
   |
   v
Connect
   |
   v
Wait for banner
   |
   +--> banner received
   |
   +--> no banner
            |
            v
       basic HTTP request
```

The resulting text is matched against known service signatures.

Examples include:

- SSH
- HTTP
- FTP
- SMTP
- MySQL
- Redis

If no banner-based identification succeeds, the scanner falls back to its known-port service map.

A port number is therefore used as a fallback hint rather than the only detection mechanism.

---

## Version Identification

Current version extraction is heuristic and banner-based.

Examples:

- SSH uses the server identification line.
- FTP uses the initial FTP response.
- HTTP looks for the `Server:` header and related response information.

The scanner reports `Unknown` when useful version evidence is not available.

---

## TLS Analysis

For services expected to use TLS, Arc-Scan attempts a TLS handshake.

Current TLS information includes:

- negotiated TLS version
- negotiated cipher
- successful TLS detection

If TLS succeeds on a service identified as HTTPS or an HTTPS alternative port, the service is marked as HTTPS.

Full certificate analysis, certificate validation, and advanced TLS auditing are not currently implemented.

---

## OS Inference

The current OS subsystem is a heuristic scorer.

Current OS hypotheses include:

```text
Linux
Windows
Network Appliance
```

Signals currently used include:

- open ports
- service patterns
- banner text
- product-related keywords

Examples:

```text
22/tcp       -> Linux score
3389/tcp     -> Windows score
135/139/445  -> Windows score
Ubuntu       -> Linux score
IIS          -> Windows score
Cisco        -> Network Appliance score
```

The resulting value is an inference, not a packet-level OS fingerprint.

---

## Device Classification

Arc-Scan currently attempts to classify a host into broad categories such as:

```text
Server
Desktop
Router
IoT
Unknown
```

The classifier uses service, banner, and keyword evidence.

This is a heuristic classifier and should not be treated as definitive device identification.

---

## Security Auditing

The current audit subsystem performs basic, non-destructive checks.

### Cleartext services

The tool flags common cleartext exposure for:

- FTP
- Telnet

### Anonymous FTP

For an open FTP service, Arc-Scan can test whether anonymous FTP login is accepted using the standard anonymous account.

If successful, it produces a structured finding.

### Finding structure

Security findings contain:

```text
Finding ID
Title
Severity
Host
Port
Service
Evidence
Recommendation
Confidence
```

---

## Data Model

Arc-Scan uses dataclasses to keep scan data structured.

### `Evidence`

```text
source
description
confidence
```

### `Service`

```text
port
protocol
state
service_name
version
banner
tls
evidence[]
```

### `Finding`

```text
finding_id
title
severity
host
port
service
evidence
recommendation
confidence
```

### `Host`

```text
ip
status
hostname
os
device_type
confidence
services[]
findings[]
```

### `ScanResult`

```text
hosts[]
start_time
duration
command
```

This model allows the same scan result to power terminal rendering and export formats.

---

## Output

The default terminal output is designed around information hierarchy rather than raw packet detail.

Typical host presentation:

```text
HOST 192.168.1.10

Status      UP
Device      Server
OS          Linux
Confidence  75%

OPEN SERVICES

PORT       SERVICE       VERSION
22/tcp     SSH           OpenSSH ...
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

Closed ports are not printed in the normal report.

Verbose mode adds additional runtime information.

---

## Export Formats

### JSON

Preserves the full nested scan structure and is the most complete machine-readable format.

### CSV

Flattens host and service information into tabular rows.

### XML

Exports hosts, services, and findings into a structured XML representation.

---

## Platform Handling

Arc-Scan currently reports:

- operating system
- Python version
- IPv4 availability
- IPv6 availability
- privilege state
- high-level scanner mode

Administrative privileges are detected differently on Unix-like systems and Windows.

The current platform layer is a basic capability/privilege indicator. It is not yet a complete low-level networking capability matrix.

---

## CLI

Current options include:

```text
--profile
--ports
--timeout
--concurrency
--audit
--verbose
--json
--csv
--xml
--self-test
--platform-info
```

### Examples

```bash
python arc_scan.py 192.168.1.1
```

```bash
python arc_scan.py 192.168.1.0/24 --profile normal
```

```bash
python arc_scan.py 192.168.1.10 --ports 22,80,443 --audit
```

```bash
python arc_scan.py 192.168.1.0/24 --json scan.json
```

```bash
python arc_scan.py --platform-info
```

```bash
python arc_scan.py --self-test
```

---

## Current Technology

| Area | Technology |
|---|---|
| Language | Python |
| CLI | `argparse` |
| Async scanning | `asyncio` |
| TCP networking | Python sockets / asyncio |
| TLS | Python `ssl` |
| Data models | `dataclasses` |
| JSON | `json` |
| CSV | `csv` |
| XML | `xml.etree.ElementTree` |
| Interactive parsing | `shlex` |
| Concurrency for blocking probes | `ThreadPoolExecutor` |

The current implementation relies primarily on the Python standard library.

---

## Project Safety Boundary

Arc-Scan is intended for authorized network administration, research, and defensive security work.

The current tool does not implement:

- credential brute forcing
- password cracking
- exploitation
- malware
- persistence
- remote command execution
- destructive testing
- evasion mechanisms

Its security checks are observation-oriented and non-destructive.

---

## Current Status

### Implemented

- Terminal CLI
- Interactive terminal mode
- IPv4 target handling
- Basic IPv6-aware target parsing
- ICMP host discovery
- TCP discovery fallback
- Concurrent TCP scanning
- Basic service detection
- Banner grabbing
- Basic version extraction
- TLS detection
- Basic OS inference
- Basic device classification
- Cleartext service audit
- Anonymous FTP audit
- Structured data models
- Terminal reporting
- JSON export
- CSV export
- XML export
- Platform information
- Basic self-test

### Not yet implemented

- UDP scanning
- ARP discovery
- dedicated ICMPv6 discovery
- deep protocol fingerprinting
- advanced OS fingerprinting
- comprehensive device fingerprinting
- full TLS certificate auditing
- adaptive scanning
- historical scan storage
- differential change detection
- AI-assisted reasoning
- distributed scanning

---

## Future Direction

The architecture is intentionally compatible with a stronger analysis layer later:

```text
Discovery
   |
   v
Observation
   |
   v
Evidence
   |
   v
Service / OS / Device Hypothesis
   |
   v
Security Findings
   |
   v
Historical Comparison
   |
   v
Adaptive Scanning
   |
   v
Optional AI Assistance
```

The important design constraint is that direct network observations remain the source of truth. Higher-level inference should explain or prioritize those observations rather than replace them.

---

## Design Principles

1. **Accuracy over feature count**
2. **Evidence before inference**
3. **Clean output over information dumping**
4. **Bounded concurrency over uncontrolled speed**
5. **Portable behavior over platform-specific assumptions**
6. **One structured result model for every output format**
7. **Advanced intelligence should remain optional**

---

## Project Identity

**Arc-Scan**  
*Network Discovery & Security Auditor*

Developer attribution used by the application:

**Developed By Manthan D.**
