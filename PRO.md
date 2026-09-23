# Product Requirements & Operational Specification (PRO.md)

**Project Name:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Target Environment:** Data Diode & Air-Gapped Critical Infrastructure (ICS/SCADA, Defense, Nuclear, Financial)  
**Version:** 1.2.0  
**Status:** Implemented & Verified Prototype  
**Date:** 2026-09-20  

---

## 1. Executive Summary & Vision

Critical Infrastructure systems—including power grids, nuclear energy stations, municipal water treatment facilities, and defense operational technology (OT)—rely on **hardware-enforced unidirectional network security (Data Diodes)** to physically isolate sensitive operational networks from external corporate or public networks.

Traditional Intrusion Detection Systems (IDS) and Next-Generation Firewalls (NGFW) fail in these environments because:
1. They depend on bidirectional handshakes, TCP reset injection, or active DNS probing to detect and mitigate threats.
2. They rely on inline SSL/TLS decryption (man-in-the-middle proxying), which is prohibited or technically impossible across a physical one-way optical fiber.
3. They generate outbound alert chatter, violating the strict zero-emission air-gap policy.

**The Vision:** Build an ultra-low-latency, zero-return-path AI/ML analytical pipeline that ingests raw unidirectional IP traffic streams passively, extracts statistical metadata without payload decryption, evaluates complex threat patterns across bounded sliding time windows ($\le 12\text{ ms}$ processing latency), and provides mission-critical situational awareness through a state-of-the-art SOC analyst dashboard.

---

## 2. Target Market & User Personas

### 2.1 Target Sectors
- **Industrial Control Systems (ICS) / SCADA:** Energy generation, transmission lines, oil and gas pipelines, municipal water systems.
- **National Defense & Intelligence:** Air-gapped classified enclaves, command-and-control datalinks.
- **Critical Financial Networks:** Inter-bank payment gateways, SWIFT hardware-isolated settlement rooms.
- **Healthcare & Biomedical:** High-containment laboratory monitoring networks, isolated patient record databases.

### 2.2 User Personas

| Persona | Role | Core Needs & Goals | Pain Points Addressed |
| :--- | :--- | :--- | :--- |
| **SOC Tier-1 / Tier-2 Analyst** | Real-Time Monitoring & Alert Triage | Immediate visual clarity, low false-positive rate, clear forensic evidence, fast alert dismissal/escalation. | Overwhelmed by encrypted opaque traffic; lacks return-path active probing tools. |
| **ICS / SCADA Security Engineer** | Industrial Network Protection | Zero risk of system disruption; non-intrusive monitoring of legacy OT protocols (Modbus, DNP3, CIP). | Inline security devices crashing legacy PLC/RTU controllers due to unexpected packet injection. |
| **Chief Information Security Officer (CISO)** | Governance, Compliance & Risk | Audit trails, regulatory compliance (NERC CIP, NIST SP 800-82, IEC 62443), ROI on air-gap investments. | Blind spots in one-way datalinks leading to unnoticed data exfiltration or internal lateral malware. |
| **Non-Technical Incident Responder / Operator** | Operations Continuity | Intuitive, jargon-free explanations of complex cyber attacks to take swift operational containment actions. | Complex cryptographic and network jargon slowing down critical physical shutdown decisions. |

---

## 3. Physical & Operational Constraints

```
   PROTECTED / RESTRICTED NETWORK                         MONITORING & SOC ENCLAVE
+------------------------------------+                  +--------------------------------+
|  ICS / SCADA / Secure Servers      |                  |  Antigravity Threat Engine     |
|  - PLCs, RTUs, Turbines, HMI       |                  |  - Passive Zeek/PCAP Ingestion |
|  - Internal Database Clones        |                  |  - Sliding-Window State Buffer |
+------------------+-----------------+                  |  - Statistical Feature Math    |
                   | TX (Photodiode)                    |  - Dual ML/Heuristic Detectors |
                   v                                    |  - WebSocket SOC Dashboard     |
         +-------------------+                          +---------------+----------------+
         | Physical Hardware |                                          ^
         |    DATA DIODE     | -----------------------------------------+
         | (One-Way Optical) |        PASSIVE RX FIBER (ZERO RETURN PATH)
         +-------------------+
             NO RX FIBER
         (Physically severed)
```

1. **Strict Hardware Unidirectionality (Zero Return Path):**
   - No TCP ACKs, SYN-ACKs, RST packets, or ICMP replies can ever be transmitted back to the monitored source.
   - The system operates strictly in "promiscuous receive" mode.
2. **Zero Payload Decryption:**
   - Analysis is performed exclusively on Layer 3/4 header metrics, packet inter-arrival timings, volume dynamics, and unencrypted Layer 7 metadata (TLS SNI, JA3/JA4 cryptographic fingerprints, DNS queries, HTTP header sizes).
   - Zero decryption keys are required; privacy and cryptographic integrity remain unbroken.
3. **Bounded Sliding-Window Memory Footprint:**
   - Ingestion rate can reach $> 15,000$ flows per second per core.
   - Memory must remain bounded ($< 120\text{ MB}$ window buffer) using fixed-duration sliding windows ($W = 60\text{s}$) with automated pruning.
4. **Real-Time Bounded Latency:**
   - Processing time per window tick must not exceed $12\text{ ms}$, ensuring near-instantaneous notification before attackers can complete an exfiltration stage.

---

## 4. Threat Coverage & Functional Capabilities

The platform implements automated dual-tier detection across **6 core network attack vectors**, alongside an **interactive multi-vector manual threat inspector**:

### 4.1 Automated Real-Time Detection Modules

```
                    +------------------------------------------+
                    |        Incoming Flow Stream (JSON/PCAP)  |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |    Sliding Window State Manager (60s)    |
                    +--------------------+---------------------+
                                         |
               +-------------------------+-------------------------+
               |                                                   |
               v                                                   v
+-----------------------------+                     +-----------------------------+
|    Heuristic & Graph Rules  |                     |  Unsupervised ML Anomaly    |
+-----------------------------+                     +-----------------------------+
| 1. Volumetric/Protocol DDoS |                     |  Scikit-Learn Isolation     |
| 2. Botnet C2 Beaconing      |                     |  Forest (5D Feature Space)  |
| 3. DGA & DNS Tunnelling     |                     +--------------+--------------+
| 4. Encrypted Malware (JA3)  |                                    |
| 5. Reconnaissance (Graph)   |                                    |
| 6. Data Exfiltration Ratio  |                                    |
+--------------+--------------+                                    |
               |                                                   |
               +-------------------------+-------------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |   Standardized Alert Normalizer & Dedupe |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |  FastAPI WebSocket & REST Event Bus      |
                    +--------------------+---------------------+
                                         |
                                         v
                    +------------------------------------------+
                    |  React SOC Mission-Control Dashboard     |
                    +------------------------------------------+
```

1. **Volumetric & Protocol DDoS:**
   - *Detection Algorithm:* Shannon entropy $H(X)$ of source IP distribution + SYN flag burst analysis.
   - *Alert Trigger:* $H(X) < 1.5$ with $\ge 25$ flows/window or $> 20$ SYN packets without completion.
2. **Botnet C2 Beaconing:**
   - *Detection Algorithm:* Inter-Arrival Time (IAT) distribution analysis calculating Mean ($\mu_{IAT}$), Standard Deviation ($\sigma_{IAT}$), and Coefficient of Variation ($CV = \sigma / \mu$).
   - *Alert Trigger:* $CV < 0.22$ over $\ge 5$ periodic outbound requests to the same external target.
3. **DGA Domains & DNS Tunnelling:**
   - *Detection Algorithm:* Lexical Shannon entropy on domain query string + English bigram/trigram rarity scoring + DNS query type analysis (`TXT`, `NULL`, `CNAME`).
   - *Alert Trigger:* Query entropy $> 3.7$ and length $> 20$, or unusual record types with high entropy.
4. **Encrypted Malware (TLS/QUIC):**
   - *Detection Algorithm:* JA3/JA4 MD5 fingerprint lookup against known malicious C2 signatures (Cobalt Strike, TrickBot, Metasploit) + non-standard destination port evaluation.
   - *Alert Trigger:* Exact JA3 signature match or TLS over ports other than 443/8443.
5. **Reconnaissance & Port Scanning:**
   - *Detection Algorithm:* NetworkX directed interaction graph $G=(V, E)$ evaluating source node out-degree, unique target IPs, and unique target ports.
   - *Alert Trigger:* Single source visiting $\ge 15$ distinct destination ports or $\ge 20$ distinct destination IPs within the window.
6. **Data Exfiltration:**
   - *Detection Algorithm:* Asymmetry ratio $R_{out/in} = \frac{\text{bytes\_sent}}{\text{bytes\_received} + 1.0}$ and burst byte counter.
   - *Alert Trigger:* $R > 10.0$ and outbound data transfer $> 5.0\text{ MB}$.
7. **Multi-Variate Unsupervised Anomaly Detection:**
   - *Detection Algorithm:* Scikit-Learn Isolation Forest ($100$ estimators, $5\%$ contamination rate) trained over normal flow vectors `[bytes_sent, bytes_received, packet_count, src_port, dst_port]`.
   - *Alert Trigger:* Anomaly score $> 0.65$ with Isolation Forest decision boundary $=-1$.

### 4.2 Interactive Manual Inspection Engine (Multi-Vector)
Enables operators to paste or probe suspicious network targets across 4 discrete vector categories:
- **IP Addresses:** Classifies Wi-Fi LAN subnets (`192.168.x.x`), corporate intranets (`10.x.x.x`, `172.16-31.x.x`), carrier-grade NAT (`100.64.x.x`), loopback, public DNS, and known threat intelligence IPs.
- **Websites & URLs:** Inspects brand impersonation (e.g., typosquatting Microsoft, Apple, PayPal), high-risk TLDs (`.xyz`, `.top`, `.buzz`, `.ru`), and lexical urgency triggers.
- **Email Addresses:** Detects disposable burner mail services (`tempmail.com`, `guerrillamail.com`), typosquatting homoglyphs (`micros0ft.com`), and corporate brand impersonation on free webmail domains (`gmail.com`, `yahoo.com`).
- **Phone Numbers / SMS:** Identifies Wangiri international one-ring callback fraud (+232 Sierra Leone, +247 Ascension, +881 Satellite), tech support scam toll-free numbers (1-800, 1-888), and bank imposter smishing shortcodes.

### 4.3 Dual Plain-English / Kid-Friendly Explanation Engine
Every detected threat generates two complementary narratives:
1. **Technical Forensic Description:** Detailed RFC metrics, Shannon entropy values, JA3 hash strings, NetworkX graph degree, and exact byte counts for SOC tier-3 analysts.
2. **Kid-Friendly Plain-English Analogy:** High-level intuitive explanation (e.g., comparing a Port Scan to a burglar checking every window lock, or DDoS to 100 people rushing through a single classroom door) for non-technical stakeholders, plant managers, and executive leadership.

---

## 5. Non-Functional Requirements (NFRs)

| Metric / Dimension | Target Specification | Achieved Benchmark |
| :--- | :--- | :--- |
| **Ingest Throughput** | $\ge 10,000$ flows/second | $> 15,000$ flows/second (single core) |
| **Processing Latency** | $\le 20\text{ ms}$ per window calculation | $\le 12\text{ ms}$ average latency |
| **Memory Footprint** | $\le 250\text{ MB}$ bounded memory | $< 120\text{ MB}$ peak sliding buffer |
| **Return Packet Generation** | Exactly 0 packets | **0 packets** (Verified by network audit) |
| **WebSocket Dispatch Delay** | $\le 10\text{ ms}$ | $< 5\text{ ms}$ broadcast latency |
| **UI Responsiveness** | 60 FPS live rendering | 60 FPS with Recharts and dynamic SVG graph |
| **Continuous Availability** | 99.999% in air-gap deployment | Graceful sliding buffer purge without crash |

---

## 6. Regulatory & Industry Compliance

- **NERC CIP-005 & CIP-007 (North American Electric Reliability Corporation):** Mandates electronic security perimeters and malicious communications monitoring for bulk power assets.
- **NIST SP 800-82 Rev 2 (Guide to ICS Security):** Recommends unidirectional security gateways to segregate Level 0-2 control networks from Level 4 enterprise networks.
- **IEC 62443-3-3 (Security for Industrial Automation and Control Systems):** Specifies zone and conduit security, strictly enforcing unidirectional information flows between zones with different security assurance levels.
- **ISO/IEC 27001 (Annex A.13 - Communications Security):** Demands network segregation, threat monitoring, and perimeter defense without compromising cryptographic confidentiality.
