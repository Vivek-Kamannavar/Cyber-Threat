# Project Tasks & Engineering Roadmap (TASKS.md)

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Current Milestone:** Phase 8 Complete (Interactive Multi-Vector SOC Platform Verified)  
**Last Updated:** 2026-09-20  

---

## 1. Project Status Overview

| Phase | Milestone Description | Status | Completion Date |
| :---: | :--- | :---: | :---: |
| **Phase 1** | Problem Formulation & Data Diode Constraints Definition | **COMPLETED** | 2026-09-10 |
| **Phase 2** | Mathematical Feature Extraction Pipeline (`engine/features.py`) | **COMPLETED** | 2026-09-12 |
| **Phase 3** | Bounded Sliding Window State Manager (`engine/window_manager.py`) | **COMPLETED** | 2026-09-14 |
| **Phase 4** | Threat Classifiers (6 Heuristics + Scikit-Learn Isolation Forest) | **COMPLETED** | 2026-09-16 |
| **Phase 5** | FastAPI REST & Asynchronous WebSocket Gateway (`backend/main.py`) | **COMPLETED** | 2026-09-17 |
| **Phase 6** | Modern SOC Analyst UI with Cyber Aesthetics (`dashboard/`) | **COMPLETED** | 2026-09-18 |
| **Phase 7** | Interactive Multi-Vector Threat Inspector (IP, URL, Email, Phone) | **COMPLETED** | 2026-09-19 |
| **Phase 8** | Plain-English / Kid-Friendly Dual Narrative Engine | **COMPLETED** | 2026-09-20 |
| **Phase 9** | Documentation Suite (`PRO.md`, `ARCHITECTUR.md`, `RULE.md`, `DESIGN.md`, `TASKS.md`, `MEMORY.md`) | **IN PROGRESS** | 2026-09-20 |
| **Phase 10**| Hardware-Accelerated DPDK / AF_PACKET & SIEM Integration | **PLANNED** | Backlog |

---

## 2. Detailed Task Breakdown & Implementation Checklist

### Phase 1: Ingestion & Passive Data Diode Core
- [x] Define zero-return-path constraint specifications.
- [x] Create Zeek log parser for `conn.log`, `dns.log`, and `ssl.log` (`ingest/parser.py`).
- [x] Implement Scapy PCAP reader for offline packet trace validation.
- [x] Build synthetic traffic generator with realistic background noise flows (`ingest/traffic_generator.py`).
- [x] Standardize internal flow dictionary schema.

### Phase 2: Feature Engineering Pipeline (`engine/features.py`)
- [x] Implement Shannon Entropy equation for character sequences and discrete distributions.
- [x] Implement Inter-Arrival Time (IAT) statistical metrics ($\mu_{\text{IAT}}, \sigma_{\text{IAT}}, CV$).
- [x] Build lexical bigram rarity scorer with baseline English corpus frequencies.
- [x] Develop NetworkX bipartite directed graph analysis for IP-port fan-out evaluation.
- [x] Implement asymmetric outbound-to-inbound byte transfer ratio calculation.

### Phase 3: Sliding Window State Manager (`engine/window_manager.py`)
- [x] Construct thread-safe $O(1)$ deque sliding window buffer.
- [x] Implement automatic time-cutoff pruning ($W = 60.0\text{ seconds}$).
- [x] Build per-source IP hash indexing for instantaneous lookup.
- [x] Implement real-time throughput metrics (pps and bps calculations).

### Phase 4: Threat Detection Modules (`engine/models/`)
- [x] **Module 1:** Volumetric & Protocol DDoS (Entropy collapse $< 1.5$ + SYN flood bursts).
- [x] **Module 2:** Botnet C2 Beaconing (Strict IAT periodicity $CV < 0.22$).
- [x] **Module 3:** DGA Domains & DNS Tunnelling (Entropy $> 3.7$, length $> 20$, `TXT`/`NULL` records).
- [x] **Module 4:** Encrypted Malware (JA3 fingerprint matching for Cobalt Strike, TrickBot, Metasploit + non-standard ports).
- [x] **Module 5:** Reconnaissance & Port Scanning (NetworkX graph fan-out: $\ge 15$ ports or $\ge 20$ hosts).
- [x] **Module 6:** Data Exfiltration ($R_{\text{asym}} > 10.0$ and bytes $> 5\text{ MB}$).
- [x] **Module 7:** Unsupervised Scikit-Learn Isolation Forest ($100$ trees, $5\%$ contamination).
- [x] Master threat detector orchestrator with 3-second deduplication cooldown (`engine/threat_detector.py`).

### Phase 5: FastAPI REST & WebSocket Streaming Gateway (`backend/main.py`)
- [x] Set up asynchronous FastAPI application and CORS middleware.
- [x] Implement `ConnectionManager` for multi-client WebSocket broadcasting (`/ws/alerts`).
- [x] Build continuous background traffic generation & detection background task.
- [x] Create administrative endpoints (`/api/health`, `/api/stats`, `/api/alerts`, `/api/alerts/clear`, `/api/detection/toggle`).
- [x] Build synthetic attack injection endpoint (`/api/simulate/{threat_type}`).

### Phase 6: SOC Analyst Visualizer (`dashboard/`)
- [x] Initialize React 18 + Vite + Tailwind CSS dashboard scaffold.
- [x] Implement dark cyber-command visual theme and glassmorphism styling (`dashboard/src/index.css`).
- [x] Develop Header with live status, diode indicators, and controls (`Header.jsx`).
- [x] Build real-time Summary KPI Cards with animated counters (`SummaryCards.jsx`).
- [x] Build interactive Attack Simulation trigger controls (`SimulationControl.jsx`).
- [x] Implement dual-axis Recharts throughput and threat pulse chart (`ThroughputChart.jsx`).
- [x] Develop interactive SVG Network Topology Graph (`NetworkTopologyGraph.jsx`).
- [x] Build live alert stream feed with severity filters (`AlertFeed.jsx`).
- [x] Implement deep-dive forensic evidence modal with raw JSON copy (`ThreatDetailsModal.jsx`).

### Phase 7: Multi-Vector Threat Intelligence Engine
- [x] Expand `/api/inspect` endpoint to handle 4 threat vectors simultaneously:
  - [x] IP Address inspection (LAN Wi-Fi, Enterprise subnets, Carrier-Grade NAT, Malicious C2).
  - [x] Website / Domain / URL inspection (Brand spoofing, typosquatting, high-risk TLDs).
  - [x] Email Address inspection (Disposable burner mail, homoglyphs, brand impersonation on free webmail).
  - [x] Phone Number / SMS inspection (Wangiri international toll fraud, tech support toll-free numbers, smishing shortcodes).
- [x] Build historical threat incident database with real-world case studies.
- [x] Develop front-end `ManualInspectionPanel.jsx` with tabbed navigation and instantaneous verdict cards.

### Phase 8: Plain-English / Kid-Friendly Dual Narrative
- [x] Map all 6 threat categories and manual inspection results to intuitive real-world analogies.
- [x] Create accessible explanation toggle in the forensic modal.
- [x] Add educational "How It Works" beginner guide modal to the header.
- [x] Add prominent welcome banner explaining one-way data diode mechanics.

### Phase 9: Comprehensive Documentation Suite (Current)
- [x] Create `PRO.md` (Product Requirements & Operational Specification).
- [x] Create `ARCHITECTUR.md` and `ARCHITECTURE.md` (System Architecture & Mathematical Formulations).
- [x] Create `RULE.md` (Operational Rules & Engineering Standards).
- [x] Create `DESIGN.md` (System & UI/UX Design Specification).
- [x] Create `TASKS.md` (Project Tasks & Engineering Roadmap).
- [ ] Create `MEMORY.md` (Project Memory, Decision Records & Context).

---

## 3. Future Engineering Roadmap (Backlog)

### Phase 10: Hardware Acceleration & High-Throughput Ingestion
- [ ] **DPDK / AF_PACKET Kernel Bypass:** Implement zero-copy raw packet capture to scale ingestion beyond $100,000$ packets/second on $10\text{ Gbps} / 100\text{ Gbps}$ optical diode datalinks.
- [ ] **eBPF Ingestion Hooks:** Leverage Linux eBPF (Extended Berkeley Packet Filter) XDP programs for high-speed packet header filtering in the kernel before reaching user space.

### Phase 11: Enterprise SIEM & STIX/TAXII Integration
- [ ] **STIX 2.1 JSON Alert Serializer:** Export standardized threat alerts into Oasis STIX 2.1 objects for automated ingestion into air-gapped SIEMs (Splunk, IBM QRadar, Elastic Security).
- [ ] **Syslog RFC 5424 Transport:** Implement encrypted local syslog transport over local Unix domain sockets.

### Phase 12: Distributed Architecture & Horizontal Clustering
- [ ] **ZeroMQ Air-Gapped Message Ring:** Decouple packet ingest engines across multiple worker nodes feeding a centralized analytical aggregator via lock-free ZeroMQ sockets.
- [ ] **Model Checkpoint Persistence:** Automated serialized saving of Isolation Forest baseline models for fast cold starts without re-training on initial boot.
