# Master Plan: UI De-Slop, Real-World Data Ingestion & Live Threat Transition (FINAL_PLAN.md)

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Repository:** `Vivek-Kamannavar/Cyber-Threat`  
**Date:** September 2026  
**Active Branch:** `feat/palette-satoshi-anti-slop`  
**Base Branch:** `main`

---

## 1. Project Roadmap: What Is Done & What Is Left (In Short)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ COMPLETED WORK                                                                         │
│  [X] Phase 1-5 Core Backend: FastAPI, Data Diode Engine, Scapy Replay, Isolation Forest│
│  [X] Strict 4-Color Palette: #FFF1D1 (Cream), #00B7CD (Teal), #DF301C (Red), #FF9100   │
│  [X] Satoshi Font Family: Weights 700 (headings) & 400 (body/all) with Pure Black Font │
│  [X] Complete AI-Slop Eradication: Zero emojis, zero status dots, zero opacity tints  │
│  [X] Dense SOC Layout: Split-pane topology, throughput line charts, alert stream       │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ REMAINING WORK (WHAT IS LEFT)                                                          │
│  [ ] 1. Real-World Ingestion via `@shrinivas-sn/adapter-ingestion`:                     │
│         - Connect live open-source CTI threat feeds (ThreatFox, Feodo Tracker, CISA)   │
│         - 1-Click "Sync Live Threat Intel" button in dashboard                         │
│         - Correlate incoming traffic flows against 10,000+ real malicious IOCs         │
│  [ ] 2. ML Model Weight Reduction & LLM Replacement:                                   │
│         - Replace heavy 300-400MB local Python model files with lightweight            │
│           heuristic + Groq/LLM inference layer for server deployment.                  │
│  [ ] 3. Production Dockerization & Server Deployment:                                  │
│         - Multi-stage Dockerfile, Nginx reverse proxy, and systemd service scripts.    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Completed Phase: UI De-Slop & Design System Audit

### 2.1 The 4-Color Strict Palette Specification
Source: `https://colorhunt.co/palette/df301cff9100fff1d100b7cd`

| Role | Color Hex | Usage & Behavioral Restraint |
| :--- | :---: | :--- |
| **Canvas & Card Background** | `#FFF1D1` | Used as the 100% solid background for page canvas, cards, panels, inputs, and modals. **Zero opacity tints** (`/10`, `/20`, `bg-black/5`) permitted. |
| **Primary Action & Telemetry** | `#00B7CD` | Upload button, Copilot action, Data Diode indicator, throughput pulse line, packet speed metrics. |
| **Critical Threat & Danger** | `#DF301C` | Critical severity tags, threat spike spikes, emergency stop button, flagged alert badges. |
| **Warning & Advisory** | `#FF9100` | High/Medium severity tags, detection pause status, facility impact advisories. |
| **Font Color** | `#000000` | Pure solid black (`#000000`) across all headings, body text, metadata, timestamps, and labels. |

### 2.2 Typography Rules
* **Font Family:** [Satoshi](https://www.fontshare.com/fonts/satoshi) loaded via Fontshare CDN (`https://api.fontshare.com/v2/css?f[]=satoshi@700,400&display=swap`).
* **Strict 2 Weights:**
  - **700 (`font-bold`):** Reserved exclusively for headings (`h1`–`h6`) and primary section titles.
  - **400 (`font-normal`):** Used for all body copy, metadata, timestamps, button text, and inputs.
* **Banned Styles:** No `font-mono`, `font-semibold`, `font-medium`, `font-black`, or italic font weights.

### 2.3 Eradicated Elements (Zero AI-Slop Guarantee)
* **Zero Emojis:** Eliminated all unicode emojis (`⚡`, `🛡️`, `🎯`, `⏱️`, `🧪`, `🔥`, `✨`, `⚠️`, `✅`, `💡`, `➔`) across all JSX components. Replaced with clean SVG icons from `lucide-react`.
* **Zero Indicator Dots:** Removed all circular status dots (`rounded-full w-2 h-2`) and pulsing animations (`animate-pulse`) from cards and legends.
* **Zero Background Washes:** Converted all translucent grey/pastel overlays (`bg-black/5`, `fillOpacity` in charts, `/10` tints) into solid `#FFF1D1` surfaces with crisp solid borders (`border-black`).

---

## 3. Real-World Threat Ingestion: `@shrinivas-sn/adapter-ingestion`

### 3.1 Package Architecture
The open-source package `@shrinivas-sn/adapter-ingestion@0.2.0` (by Shrinivas Nemagoudar) provides a production-grade **fetch ➔ extract ➔ dedupe ➔ store** ETL engine with:
1. **Zero External Dependencies:** Native Fetch and crypto hashing.
2. **Canary Shape-Drift Detection:** Emits warning if the remote threat intelligence site changes structure.
3. **Atomic File Storage & Mutex Locking:** Prevents race conditions during background sync.
4. **Content-Hash Deduplication:** Stores only unique, new threat indicators without duplicates.

### 3.2 Target Free Open Threat Feeds (Zero API Key Required)
1. **ThreatFox (abuse.ch):** Live Indicators of Compromise (C2 IP addresses, malware payloads, malicious ports).
2. **Feodo Tracker (abuse.ch):** Active botnet C2 IP address blocklist.
3. **URLhaus (abuse.ch):** Newly discovered malware distribution endpoints.
4. **CISA Known Exploited Vulnerabilities (KEV):** Critical exploited CVEs and target infrastructure.

### 3.3 Integration Blueprint

```
┌────────────────────────────────────────────────────────┐
│          REAL-WORLD THREAT INTELLIGENCE SOURCES        │
│  - ThreatFox (abuse.ch): Live C2 IPs & Malicious Ports │
│  - Feodo Tracker: Active Botnet Command & Control      │
│  - URLhaus: Active Malware Distribution Domains        │
│  - CISA Known Exploited Vulnerabilities Catalog        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│     @shrinivas-sn/adapter-ingestion RUNNER             │
│  - Location: scripts/ingest_threat_intel.mjs           │
│  - Adapters: adapters/threatfox.json, feodo.json       │
│  - Runs: Via 1-click API endpoint or scheduled cron    │
│  - Storage: data/threat_feeds/normalized_iocs.json     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│            CYBER-THREAT DETECTION ENGINE               │
│  - FastAPI loads IOC database into memory in set()     │
│  - Incoming PCAP / Sniffed flows matched in O(1) time  │
│  - Instant high-confidence alert emitted if IP matches │
└────────────────────────────────────────────────────────┘
```

### 3.4 User Workflow (From Synthetic to Real-World)
1. Analyst clicks **"Sync Real-World Threat Feeds"** on the dashboard.
2. The backend triggers the `@shrinivas-sn/adapter-ingestion` runner.
3. In under 3 seconds, 5,000+ active worldwide malware/C2 IPs are downloaded, deduped, and cached.
4. When any real traffic flows through the data diode or PCAP is replayed, any connection to these active threat IPs triggers an immediate `CRITICAL` alert with real attribution metadata.

---

## 4. Edge Cases & Verification Plan

| Area | Edge Case | Mitigation & Assertion |
| :--- | :--- | :--- |
| **Feed Ingestion** | Feed source down (500/503) | `@shrinivas-sn/adapter-ingestion` records error report, retains existing cached IOCs, returns clean status code. |
| **Feed Ingestion** | Feed schema change | Canary threshold detects missing field ratio and flags `stale` without crashing the ingestion process. |
| **Detection Engine**| 100,000+ IOCs loaded | Store in Python `set()` or SQLite index; lookup latency stays under 0.05ms per flow. |
| **UI Rendering** | 500+ alerts logged | Alert feed capped at latest 100 items with export to CSV/JSON available. |
| **Typography** | Fontshare CDN latency | Fallback to `sans-serif` specified in CSS, text remains readable and black. |

---

## 5. Git PR Execution & Verification Prompt

### 5.1 Branch & Commit Info
- **Branch:** `feat/palette-satoshi-anti-slop`
- **Base:** `main`
- **Commit Summary:** Complete UI de-slop, strict 4-color palette, Satoshi typography (700/400), black font color, zero emojis, zero dots, zero opacity background tints.

### 5.2 Verification Prompt for Local Testing & Merging
Below is the copy-paste prompt to verify and merge this branch:

```bash
# 1. Fetch and checkout the PR branch
git fetch origin
git checkout feat/palette-satoshi-anti-slop

# 2. Verify backend test suite (All 24 pytest cases must pass)
.\venv\Scripts\python -m pytest tests/ -v

# 3. Verify frontend production build (Must pass with 0 errors)
cd dashboard
npm install
npm run build

# 4. Start local servers to verify UI in browser
# Terminal 1: Backend
cd E:\Cyber-Threat
.\venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Dashboard
cd E:\Cyber-Threat\dashboard
npx vite --force

# 5. Browser Verification Checklist:
# - Open http://localhost:5173
# - Verify background is solid warm cream (#FFF1D1) with NO grey/pastel tints
# - Verify text is pure black (#000000) using Satoshi font
# - Verify headings use weight 700 and body text uses weight 400
# - Verify zero emojis and zero circular indicator dots on cards
# - Trigger a simulation (e.g. DDoS Flood) and open AI Copilot drawer
# - Verify AI Copilot drawer and Threat Evidence modal follow the exact palette

# 6. Merge to main once verified
git checkout main
git merge feat/palette-satoshi-anti-slop
git push origin main
```
