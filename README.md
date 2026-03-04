# 🔍 C-Binary-Forensics: High-Speed PCAP Metadata Extractor

A high-performance Digital Forensics tool written in C for rapid triage of network traffic. 

### 🚀 The Problem
SOC Analysts often face massive PCAP files that are too large for manual Wireshark analysis or too expensive to index into a SIEM (Splunk/Wazuh) in their raw form.

### 🛠️ The Solution
This tool parses the **Binary Structure** of a PCAP file at the bit level. It extracts core telemetry into a structured CSV format, reducing data volume by over 95% while preserving the forensic "truth" needed for timing and volume analysis.

### 🔬 Technical Deep Dive
- **Memory Efficient:** Uses `fseek` for stream-oriented parsing. No RAM-bloat.
- **Binary Mapping:** Manually maps the Global PCAP Header (24 bytes) and Record Headers (16 bytes).
- **Use Case:** Perfect for detecting **C2 Beacons** via Delta-Time analysis or identifying **Data Exfiltration** via packet-size outliers.
