# Master Implementation Plan: Real-World Ingestion, ML-to-LLM Transition & SOC Workstation

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Repository:** `Vivek-Kamannavar/Cyber-Threat`  
**Active Fork:** `shrinivas-sn/Cyber-Threat`  
**Active Branch:** `feat/palette-satoshi-anti-slop`  
**PR URL:** https://github.com/Vivek-Kamannavar/Cyber-Threat/pull/3  
**Date:** September 2026

---

## 1. Executive Summary & Status

This master plan lays out the exact execution path for moving from the current state (clean SOC UI + synthetic simulation engine) to a **100% production-ready, real-world cyber threat detection platform**.

### Current State (Completed in PR #3)
- [x] Merged 5-Phase backend architecture (Data Diode emulation, unidirectional flow parsing, Isolation Forest, and Groq Copilot).
- [x] Strict 4-color design system enforced: `#FFF1D1` (Warm Cream), `#00B7CD` (Teal), `#DF301C` (Crimson Red), `#FF9100` (Orange), Pure Black font (`#000000`).
- [x] Satoshi typography with strictly 2 weights: 700 for headings, 400 for body/labels.
- [x] Zero AI slop: all emojis, circular status dots, glowing drop shadows, and opacity tint washes eliminated.

### Next Execution Stages
- **Phase 6:** Ingesting Real-World Live Threat Intelligence with `@shrinivas-sn/adapter-ingestion`.
- **Phase 7:** Eliminating Heavy Python ML Models (300–400MB) & Replacing with Lightweight LLM Inference Layer for Server Deployment.
- **Phase 8:** 1-Click Frontend Live Threat Sync & Real-Time Flow Correlation.
- **Phase 9:** Verification, Edge Case Testing & Mainline Merge.

---

## 2. Phase 6: Ingesting Real-World Threat Intelligence with `@shrinivas-sn/adapter-ingestion`

### 2.1 Package Overview
- **Package:** `@shrinivas-sn/adapter-ingestion@0.2.0` (Published by Shrinivas Nemagoudar, MIT License).
- **Core Mechanism:** Generic Fetch ➔ Extract ➔ Dedupe ➔ Store pipeline with built-in canary shape-drift detection.
- **Why it fits:** It allows fetching live, publicly available threat intelligence feeds (C2 IPs, malware domains, malicious ports) from open sources with zero external dependencies and zero API fees, ensuring the system operates with real-world IOCs (Indicators of Compromise).

### 2.2 Target Free Threat Intelligence Feeds
1. **ThreatFox (abuse.ch):** Live Indicators of Compromise (C2 IP addresses, malware payloads, malicious ports).
   - Feed Endpoint: `https://threatfox-api.abuse.ch/api/v1/`
2. **Feodo Tracker (abuse.ch):** Active botnet C2 IP address blocklist.
   - Feed Endpoint: `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json`
3. **URLhaus (abuse.ch):** Active malware distribution URLs and hostnames.
   - Feed Endpoint: `https://urlhaus-api.abuse.ch/v1/urls/recent/`
4. **CISA Known Exploited Vulnerabilities (KEV):** Critical exploited CVEs and target infrastructure.
   - Feed Endpoint: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

### 2.3 Detailed File Structure & Implementation Steps

#### Step 6.1: Install Package & Create Ingestion Service
In project root:
```bash
npm install @shrinivas-sn/adapter-ingestion --save
```

Create directory layout:
```
ingestion/
├── adapters/
│   ├── threatfox.adapter.json
│   ├── feodotracker.adapter.json
│   └── cisa_kev.adapter.json
├── fixtures/
│   └── sample_threat_feed.json
├── runs/
└── runner.mjs
```

#### Step 6.2: Create Adapter Configurations (`ingestion/adapters/`)
`feodotracker.adapter.json`:
```json
{
  "host": "feodotracker.abuse.ch",
  "version": 2,
  "fetch": {
    "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
    "method": "GET",
    "timeout_ms": 30000,
    "max_records": 10000
  },
  "extract": {
    "records_path": "$",
    "fields": {
      "ip_address": "ip_address",
      "port": "port",
      "malware": "malware",
      "first_seen": "first_seen_utc",
      "status": "status"
    }
  },
  "dedupe": {
    "primary_key": "ip_address"
  },
  "canary": {
    "min_records": 10,
    "required_fields": ["ip_address", "malware"]
  }
}
```

#### Step 6.3: Ingestion Runner Script (`ingestion/runner.mjs`)
- Executes `@shrinivas-sn/adapter-ingestion` pipeline.
- Writes normalized IOCs to `data/threat_feeds/active_iocs.json`.
- Emits clean report JSON with summary counts of new, changed, and active threats.

#### Step 6.4: Backend Integration (`backend/routes/feeds.py`)
Add FastAPI routes:
- `POST /api/feeds/sync`: Spawns the adapter ingestion runner asynchronously, updates the in-memory malicious IP set.
- `GET /api/feeds/status`: Returns current feed metrics (last sync timestamp, active IOC count, source breakdown).

#### Step 6.5: High-Speed O(1) Flow Correlation (`engine/threat_detector.py`)
- Load `active_iocs.json` into a Python in-memory `set()` of `(ip, port)` and `ip`.
- During live packet capture or PCAP replay:
  - Check `flow.src_ip` and `flow.dst_ip` against the active IOC set in $O(1)$ time ($< 0.02\text{ ms}$).
  - If a match is found: immediately flag as `CRITICAL` severity with threat class `Botnet C2 Beaconing (ThreatFox/Feodo Verified)`.

---

## 3. Phase 7: Eliminating Heavy Python ML Models (300–400MB) & Replacing with LLM Inference Layer

### 3.1 The Problem with Heavy Local ML Models
- Storing Scikit-Learn `.pkl` / `.joblib` files and large PyTorch/TensorFlow weights bloats the project repository to 300–500MB.
- Heavy Python ML dependencies require C-extensions (NumPy, Scipy, Scikit-learn), causing slow Docker builds, memory spikes on server deployment, and cold-start latency.
- Statistical anomaly detection on network traffic (DDoS rate bursts, port scans, beacons) can be evaluated with deterministic mathematical algorithms in microsecond time, while semantic attack attribution is best handled by an LLM layer.

### 3.2 Replacement Architecture: Lightweight Heuristics + Cloud LLM
1. **Mathematical Feature Engine (Zero File Weight, Microsecond Speed):**
   - **Shannon Entropy of Ports & Packet Sizes:** Identifies encrypted payloads and random port scanning.
   - **Inter-Arrival Time (IAT) Variance & Jitter:** Detects programmatic C2 beaconing.
   - **Asymmetric Flow Ratio ($R_{\text{asym}}$):** Detects exfiltration across unidirectional links.
   - All written in pure, standard Python with zero heavy binary weights.

2. **Cloud LLM Layer (Groq Llama 3.3 70B / OpenAI):**
   - Replaces heavy local classification models with fast API inference (sub-500ms latency via Groq).
   - Generates contextual incident analysis, plain-language explanations, and exact gateway firewall mitigation commands on demand.
   - Total disk footprint: **0 MB**.

3. **Deployment Benefit:**
   - Server Docker image size drops from **1.2 GB ➔ under 120 MB**.
   - Deployment to VPS / cloud runs in seconds with minimal RAM requirements.

---

## 4. Phase 8: 1-Click Frontend Live Threat Sync & Real-Time Flow Correlation

### 4.1 Dashboard UI Additions (Adhering to Strict Design Rules)
- **Top Command Bar Button:** "Sync Threat Feeds" button in `#FFF1D1` with `#00B7CD` text and crisp black border.
- **Feed Status Pill:** "Feeds: 12,480 IOCs Active" displayed cleanly in black text.
- **Trigger Behavior:**
  - Clicking triggers `POST /api/feeds/sync`.
  - Shows spinning `Loader2` during sync.
  - Automatically updates the live feed and topology graph with real-world verified alerts.

---

## 5. Comprehensive Edge Cases & Test Matrix

| Area | Test Case | Edge Case | Expected System Behavior |
| :--- | :--- | :--- | :--- |
| **Ingestion** | TC-ING-01 | Remote feed times out (HTTP 504) | Ingestion runner times out at 30s, falls back to existing cached IOCs, logs clean warning without crash. |
| **Ingestion** | TC-ING-02 | Feed structure changes (shape drift) | Canary in `@shrinivas-sn/adapter-ingestion` catches missing field ratio, flags `stale`, and preserves previous store. |
| **Ingestion** | TC-ING-03 | Duplicate IPs across ThreatFox & Feodo | Content-hash deduplication merges duplicates into single record with combined tags. |
| **Detection** | TC-DET-01 | 50,000 active IOCs in memory | Python hash set lookup remains $< 0.05\text{ ms}$ per packet flow; zero throughput bottleneck. |
| **Detection** | TC-DET-02 | Benign internal IP collides with public feed | Whitelist filter (`192.168.0.0/16`, `10.0.0.0/8`) prevents false alerts on internal workstations. |
| **LLM Layer** | TC-LLM-01 | Cloud Groq API key missing or rate-limited | Engine automatically falls back to deterministic rule explanation; zero user disruption. |

---

## 6. Prompt to Fetch Forked PR & Start Executing

Give the prompt below to an AI assistant or run it directly in your terminal to fetch this forked PR and immediately begin executing Phase 6 and Phase 7:

```markdown
You are working on the repository `Vivek-Kamannavar/Cyber-Threat` located at `E:\Cyber-Threat`.
The UI overhaul (4-color palette, Satoshi font 700/400, zero emojis, zero dots, zero tints) has been completed and pushed to PR #3 (`https://github.com/Vivek-Kamannavar/Cyber-Threat/pull/3`) on the fork branch `feat/palette-satoshi-anti-slop`.

YOUR OBJECTIVE:
1. Fetch and checkout the branch `feat/palette-satoshi-anti-slop` from `fork` (or `origin`).
2. Read the master blueprint at `FINAL_PLAN.md`.
3. Execute Phase 6 and Phase 7 as specified in `FINAL_PLAN.md`:
   - Install `@shrinivas-sn/adapter-ingestion` and set up the threat feed adapters for ThreatFox and Feodo Tracker.
   - Create `ingestion/runner.mjs` and connect the FastAPI `/api/feeds/sync` endpoint.
   - Wire the in-memory IOC set into `engine/threat_detector.py` for O(1) flow correlation.
   - Deprecate heavy Python ML files in favor of lightweight mathematical heuristics + Groq LLM inference layer to prepare for lightweight server deployment.
   - Add the "Sync Threat Feeds" button to the frontend header strictly following the Satoshi font and 4-color palette rules.
4. Verify backend unit tests and frontend production build pass with zero errors.
```
