# Master Engineering Plan: Production Hardening, Real-World Data Ingest & AI Copilot

> **Document Purpose:** This implementation plan provides a comprehensive, self-contained, phase-by-phase roadmap for hardening the **Cyber-Threat** detection platform. Any developer or autonomous AI agent can execute this plan step-by-step using standard Python and Node.js toolchains without external assumptions.

---

## 1. Executive Summary & Gaps Identified

A comprehensive audit of the repository revealed the following critical architectural and engineering gaps that must be resolved to elevate this project from a prototype into an enterprise-grade Critical Infrastructure SOC tool:

### 1.1 Backend & Engine Vulnerabilities
1. **Concurrency Race Conditions:** The in-memory sliding window ring buffer (`SlidingWindowManager` in `engine/window_manager.py`) is concurrently mutated by the background simulation worker and read by REST/WebSocket handlers without thread locks. Under production flow rates, this raises `RuntimeError: dictionary changed size during iteration`.
2. **Ephemeral Incident State (Zero Persistence):** Threat alerts are stored strictly in a Python in-memory list (`self.alerts_history = []`). Any server restart or crash permanently wipes all historical incident forensic data.
3. **Hardcoded Detection Thresholds:** Core detection boundaries (e.g., $5\text{ MB}$ exfiltration volume, $CV < 0.22$ beaconing threshold, $15\text{ ports}$ scan limit) are hardcoded directly within `engine/models/heuristic_rules.py`, preventing operators from adjusting sensitivity without altering core engine source code.
4. **Synthetic ML Cold-Start:** The `FlowAnomalyDetector` (`engine/models/isolation_forest.py`) generates 200 random normal values on every process boot rather than serializing and persisting a pre-calibrated baseline model (`model.joblib`).
5. **No Input Sanitation & Pydantic Validation on Inspection:** The manual inspection endpoint lacks strict schema validation and bounded rate limiting.

### 1.2 Ingestion & Real-World Data Gap
1. **Synthetic-Only Pipeline:** The system currently relies on mathematical synthesis (`ingest/traffic_generator.py`). While `ingest/parser.py` contains basic parsing logic, there is no HTTP/WebSocket file-upload ingestion pipeline to upload, parse, and replay real-world Wireshark `.pcap` captures or Zeek log files (`conn.log`, `dns.log`, `ssl.log`).

### 1.3 LLM / User Comprehension Gap
1. **No Interactive Remediation Guidance:** While the rule engine emits simple string analogies, security operators lack dynamic, context-aware remediation checklists, mitigation command generation (e.g., IPTables/Suricata block rules), and interactive Q&A regarding specific threats.

### 1.4 Frontend & UX Limitations
1. **Static / Mocked Topology:** `NetworkTopologyGraph.jsx` uses a hardcoded diagram instead of dynamically parsing active communicating nodes from the current sliding window.
2. **Missing SOC Utility Operations:** The interface lacks alert search, severity filtering (Critical, High, Medium, Low), incident acknowledgment/status transitions, and forensic export (JSON/CSV).
3. **Missing File Upload Interface:** Operators have no UI component to upload real PCAP or Zeek files into the engine.

---

## 2. Target Architecture & Key Upgrades

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA INGESTION LAYER                            │
│  [Synthetic Generator]   OR   [PCAP / Zeek File Upload: /api/ingest]  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼ (Normalized Unidirectional Flows)
┌────────────────────────────────────────────────────────────────────────┐
│                     DETECTION & ENGINE LAYER                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Thread-Safe Sliding Window (asyncio.Lock, 60s Ring Buffer)       │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    ├────────────────────────────────┐  │
│                                    ▼                                ▼  │
│                     ┌──────────────────────────────┐ ┌───────────────┐ │
│                     │ 6 Deterministic Heuristics   │ │ Isolation     │ │
│                     │ (Entropy, IAT, Fan-out, etc) │ │ Forest (ML)   │ │
│                     └──────────────┬───────────────┘ └───────┬───────┘ │
└────────────────────────────────────┼─────────────────────────┼─────────┘
                                     │ (Alert Triggers)        │
                                     ▼                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PERSISTENCE & ENRICHMENT LAYER                       │
│  ┌─────────────────────────────┐    ┌───────────────────────────────┐  │
│  │ SQLite Database (WAL Mode)  │    │ Groq Free Cloud LLM Service   │  │
│  │ Alerts, Flows, Incidents    │    │ (Llama 3.3 70B / 3.1 8B)      │  │
│  └─────────────────────────────┘    │ Incident Briefs & SOC Chat    │  │
│                                     └───────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼ (FastAPI WebSockets + REST)
┌────────────────────────────────────────────────────────────────────────┐
│                     PRODUCTION SOC DASHBOARD                           │
│  - Real-Time Live Telemetry Stream     - PCAP / Zeek Drag-and-Drop     │
│  - Dynamic Network Topology Graph      - Alert Filter & CSV Export     │
│  - Interactive AI SOC Copilot Drawer   - Manual Vector Inspector       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phased Step-by-Step Implementation Roadmap

### Phase 1: Backend Hardening, Concurrency & Persistence

#### Objectives
Eliminate race conditions, add SQLite persistent storage for all flows and alerts, and externalize all detection thresholds into a centralized configuration module.

#### Implementation Steps
1. **Thread-Safe Window Manager:**
   - Update `engine/window_manager.py` to incorporate an `asyncio.Lock` or reentrant lock around all `add_flow`, `get_recent_flows`, and `purge` operations.
   - Return defensive deep-copies or immutable tuples during window queries to guarantee zero iteration mutation errors.
2. **Centralized Configuration System:**
   - Expand `backend/config.py` to parse environment variables (with fallback defaults) for:
     - `DDOS_ENTROPY_THRESHOLD` (default: 1.5)
     - `DDOS_RATE_THRESHOLD` (default: 25)
     - `C2_CV_THRESHOLD` (default: 0.22)
     - `DNS_ENTROPY_THRESHOLD` (default: 3.7)
     - `RECON_PORT_THRESHOLD` (default: 15)
     - `EXFIL_ASYMMETRY_RATIO` (default: 10.0)
     - `EXFIL_BYTES_THRESHOLD` (default: 5,000,000)
     - `ALERT_COOLDOWN_SECONDS` (default: 3.0)
     - `SQLITE_DB_PATH` (default: `backend/data/cyber_threat.db`)
     - `GROQ_API_KEY` (optional, default: `""`)
     - `GROQ_MODEL` (default: `"llama-3.3-70b-versatile"`)
   - Update `engine/models/heuristic_rules.py` to reference these configuration values rather than hardcoded literals.
3. **SQLite Database Layer:**
   - Create `backend/database.py` using standard Python `sqlite3` (with WAL mode enabled for high concurrent read/write throughput).
   - Define tables:
     - `alerts`: `alert_id` (PK), `timestamp`, `threat_class`, `confidence_score`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `evidence_json`, `status` (default: 'OPEN'), `ai_brief_json`.
     - `flow_history`: `id` (Auto PK), `timestamp`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bytes_sent`, `bytes_recv`.
   - Update `ThreatDetector` to asynchronously persist all raised alerts to SQLite.
   - Add database migration helper that auto-creates tables if they do not exist.
4. **Isolation Forest Persistence:**
   - Add `save_model(filepath)` and `load_model(filepath)` methods to `engine/models/isolation_forest.py` using `joblib`.
   - If a saved `model.joblib` exists, load it on startup; otherwise, calibrate the baseline and persist it.

#### Verification Checkpoint (Phase 1)
```bash
.\venv\Scripts\python.exe -m pytest tests/test_phase1_backend.py -v
```
*Expected Result:* Database tables created, multithreaded flow additions execute without iteration crashes, alerts persist across detector re-initialization.

---

### Phase 2: Real-World PCAP & Zeek Log Ingestion Pipeline

#### Objectives
Enable the platform to ingest real-world network traffic captures (PCAP files from Wireshark/tcpdump) and Zeek log files (`conn.log`, `dns.log`, `ssl.log`), parse them into standardized flow tuples, and stream them through the detection engine.

#### Implementation Steps
1. **PCAP Stream Extractor:**
   - Create `ingest/pcap_loader.py` using `scapy.utils.PcapReader` (streaming iterator to prevent loading multi-gigabyte PCAPs directly into RAM).
   - Extract standard 5-tuples: IP source/destination, TCP/UDP ports, packet lengths, TCP flags (SYN/ACK/FIN), and TLS Client Hello SNI/JA3 fingerprints where present.
   - Calculate inter-packet arrival times and aggregate raw packets into unidirectional flow summaries.
2. **Zeek Multi-Log Synchronizer:**
   - Enhance `ingest/parser.py` to support multi-file log ingestion, correlating `conn.log` entries with corresponding `dns.log` (by query UID) and `ssl.log` (by server name / JA3).
3. **Ingestion REST API Endpoints:**
   - Add `POST /api/ingest/upload`: Accepts multipart file upload (`.pcap`, `.pcapng`, `.log`).
   - Add query parameter `playback_speed`: Controls streaming replay rate (`1x` real-time, `5x`, `10x`, or `instant_batch`).
   - Add `POST /api/ingest/stop`: Stops any currently running file replay.
   - Add `GET /api/ingest/status`: Returns current ingestion source, total flows ingested, and processing progress.

#### Verification Checkpoint (Phase 2)
```bash
.\venv\Scripts\python.exe -m pytest tests/test_phase2_ingest.py -v
```
*Expected Result:* Sample `.pcap` and `conn.log` files uploaded via API correctly parse into normalized flow objects and trigger corresponding detection heuristics.

---

### Phase 3: Free Groq AI Incident Copilot & Natural Language Explanations

#### Objectives
Integrate Groq's high-speed free API tier (`llama-3.3-70b-versatile` or `llama-3.1-8b-instant`) to provide human-readable executive incident summaries, root-cause analysis, actionable mitigation checklists, and an interactive SOC analyst chatbot.

#### Implementation Steps
1. **Groq Client Integration Service:**
   - Create `backend/services/groq_service.py`.
   - Implement graceful fallback: If `GROQ_API_KEY` is not supplied, generate a structured rule-based deterministic summary so the application remains 100% functional offline.
   - Use official Groq SDK (`groq` package) with strict temperature ($0.2$) and bounded token limits to stay well within free-tier limits ($30\text{ requests/min}$, $14,400\text{ requests/day}$).
2. **Structured Response Formatting:**
   - Define target response schema:
     ```json
     {
       "summary": "Plain English description of what occurred",
       "severity_rating": "CRITICAL | HIGH | MEDIUM | LOW",
       "attack_vector_breakdown": "Explanation of the protocol/methodology used",
       "potential_business_impact": "Operational risks for the air-gapped facility",
       "recommended_remediation_steps": [
         "Immediate action 1",
         "Immediate action 2"
       ],
       "firewall_mitigation_rule": "iptables -A INPUT -s ... -j DROP"
     }
     ```
3. **API Endpoints for AI Copilot:**
   - `POST /api/ai/analyze-alert/{alert_id}`: Generates or fetches cached structured analysis for a specific alert. Results are stored in the SQLite database to prevent redundant API calls.
   - `POST /api/ai/chat`: Accepts conversation history and an alert context, allowing the operator to ask follow-up questions (e.g., *"How do I verify if IP 192.168.10.15 is compromised?"*).

#### Verification Checkpoint (Phase 3)
```bash
.\venv\Scripts\python.exe -m pytest tests/test_phase3_ai.py -v
```
*Expected Result:* Correctly formats prompts, parses structured JSON from Groq, gracefully handles missing API keys with offline fallbacks, and caches results to SQLite.

---

### Phase 4: UI Overhaul: Removing AI-Slop & Delivering Non-Technical Clarity

#### Objectives
Strip out superficial, AI-generated template styling ("AI slop") and redesign the frontend into a high-clarity, professional enterprise interface that makes complex cyber threats immediately understandable to **both seasoned SOC engineers and non-technical stakeholders**.

#### 1. Audit of Generic "AI Slop" Patterns Marked for Removal
* ❌ **The "Hollywood Hacker" Aesthetic:** Remove overused dark-space `#0a0e17` backgrounds, oversaturated cyan/teal neon glow filters (`shadow-[0_0_20px_...]`), and decorative scanline effects that mimic sci-fi movie tropes rather than functional enterprise software.
* ❌ **Fake / Static Topology Visuals:** The current `NetworkTopologyGraph.jsx` is an ornamental SVG with hardcoded, simulated nodes that do not reflect actual live network telemetry.
* ❌ **Raw JSON Dumps in Alerts:** Replace walls of unformatted JSON metrics (`asymmetry_ratio: 1475.88`, `CV: 0.016`) with visual meters, risk indicators, and human-first explanations.
* ❌ **Jargon-Heavy Simulation Buttons:** Replace obscure buttons like `dga_dns` or `c2_beacon` with plain-language scenario descriptions with tooltip breakdowns.
* ❌ **Non-Actionable Dead Ends:** Add real workflow actions: search, severity filtering, alert acknowledgment, incident status tagging, and forensic data export (CSV/JSON).

#### 2. Non-Technical Human Clarity Architecture
To ensure anyone (including executives, facility managers, and non-technical operators) can understand network status at a glance:
* **The "Traffic Light" Facility Status Banner (Top of Screen):**
  - **🟢 NORMAL (Green):** "All Systems Secure. Unidirectional data diode operating normally with zero anomalous activity."
  - **🟡 ELEVATED ADVISORY (Yellow):** "Unusual Traffic Pattern Detected. Single source exhibiting high connection rates."
  - **🔴 CRITICAL THREAT DETECTED (Red with Audio Alert):** Prominently displays: *"Active Data Theft / Attack In Progress: Computer in Room 4 is sending an abnormally massive file to an unauthorized overseas server."*
* **Simplified 3-Stage Visual Pipeline:**
  - A clean, animated interactive visual showing:
    `[Protected Internal SCADA Vault] ──(Physical One-Way Diode)──► [External Network]`
  - Normal traffic pulses as calm green or blue dots.
  - When an attack occurs, the offending path lights up with a clear warning tag (e.g., *"Unauthorized Connection"* or *"DDoS Flood"*), pinpointing exactly where the threat originates.
* **Dual-View Toggle ("Executive / Simple View" vs "Deep SOC Forensic View"):**
  - **Simple Mode (Default):** Highlights plain-English storylines, impact summaries, and recommended actions without overwhelming numbers.
  - **Expert Mode (1-Click Toggle):** Unlocks deep technical details: Shannon entropy graphs, Inter-Arrival Time distributions, raw packet hex/metadata, and JA3 cryptographic fingerprints.

#### 3. Frontend Implementation Steps
1. **Design System & Typography:**
   - Migrate to clean Slate neutrals (`#0f172a` base, `#1e293b` surfaces, `#334155` borders) with crisp typography (Inter/Geist font stacks) and WCAG AAA contrast ratios.
   - Remove all generic blur backdrops and excessive glowing drop-shadows.
2. **PCAP / Zeek Upload Drawer (`components/FileUploadModal.jsx`):**
   - Provide a clean drag-and-drop zone for real `.pcap`, `.pcapng`, and Zeek `.log` files with playback speed controls (1x, 5x, Instant).
3. **Actionable Incident Feed (`components/AlertFeed.jsx`):**
   - Filter bar: Search by IP/hostname, filter by severity (Critical / High / Medium / Low), filter by status (Open / Acknowledged / Resolved).
   - Export Button: Instant export of selected alerts to structured CSV or JSON.
4. **Interactive AI Incident Copilot Drawer (`components/AiCopilotDrawer.jsx`):**
   - Slide-over drawer when clicking any alert, displaying:
     - Plain-English Executive Summary
     - Business / Facility Impact Assessment
     - Step-by-Step Remediation Checklist
     - Copyable Firewall / IPTables command
     - Interactive Chatbot for asking questions about the threat.
5. **Dynamic Real-Time Topology (`components/NetworkTopologyGraph.jsx`):**
   - Dynamically renders active host nodes discovered from the sliding window ring buffer, showing live communication arcs and color-coded threat paths.

#### Verification Checkpoint (Phase 4)
```bash
cd dashboard && npm run build
```
*Expected Result:* Clean production build with zero warnings, accessible contrast, and verified toggle between Executive and Forensic views.

---

### Phase 5: Automated Test Suite & Edge Case Hardening

#### Objectives
Create a comprehensive test suite covering mathematical precision, network boundary cases, and system resilience.

#### Test Matrix & Edge Cases
1. **Mathematical Edge Cases (`tests/test_math_features.py`):**
   - `calculate_shannon_entropy`: Empty string, single character repeated 1,000 times, full alphabet uniform distribution.
   - `calculate_iat_stats`: 0 timestamps, 1 timestamp, identical timestamps (zero division check in $CV = \sigma / \mu$).
   - `calculate_dns_ngram_score`: Non-ASCII characters, subdomains with 50+ levels, domain strings $> 255$ characters.
   - `calculate_byte_asymmetry`: Outbound bytes $> 0$ with 0 inbound bytes (handled by $+ 1.0$ denominator smoothing).
2. **Detection Heuristic Boundaries (`tests/test_heuristics.py`):**
   - Borderline DDoS: Rate at exactly 24 flows (no trigger) vs 25 flows with low entropy (trigger).
   - Jittered C2: $CV = 0.21$ (trigger) vs $CV = 0.23$ (no trigger).
   - Clean traffic: Ensure 1,000 continuous benign flows generate 0 false positive alerts.
3. **API & WebSocket Stress Tests (`tests/test_api_endpoints.py`):**
   - Verify WebSocket reconnection resilience and broadcast message formatting.
   - Verify concurrent file uploads and rate limit handling.

#### Verification Checkpoint (Phase 5)
```bash
.\venv\Scripts\python.exe -m pytest tests/ -v --tb=short
```
*Expected Result:* 100% of unit and integration tests passing.

---

## 4. Verification Checkpoints for Autonomous Execution

When executing this plan, the developer or agent must verify progress after each phase using the following commands:

| Checkpoint | Target Phase | Command | Success Metric |
| :--- | :--- | :--- | :--- |
| **CP-1** | Backend & DB | `.\venv\Scripts\python.exe -m pytest tests/test_phase1_backend.py` | Exit code 0, tables created, locks verified |
| **CP-2** | PCAP Upload | `.\venv\Scripts\python.exe -m pytest tests/test_phase2_ingest.py` | Exit code 0, PCAP parsed & flows ingested |
| **CP-3** | Groq AI Service | `.\venv\Scripts\python.exe -m pytest tests/test_phase3_ai.py` | Exit code 0, fallback works, schema validated |
| **CP-4** | Frontend Build | `npm --prefix dashboard run build` | Exit code 0, production bundle compiled |
| **CP-5** | End-to-End Suite | `.\venv\Scripts\python.exe -m pytest tests/` | All tests pass, zero regressions |

---

## 5. Branch & PR Strategy

1. **Current Branch:** `chore/docs-restructure`
2. **Review & Merge Process:**
   - Commit `PLAN.md` and docs migration files.
   - Push branch to GitHub: `git push -u origin chore/docs-restructure`.
   - Submit Pull Request with a clear summary referencing this document.
   - The repository owner can review and merge the PR.
   - Future implementation phases can be executed sequentially against the verified checkpoints defined in this plan.
