# System & UI/UX Design Specification (DESIGN.md)

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Design Philosophy:** Mission-Critical SOC Cyber-Command Visual Language  
**Framework:** React 18, Tailwind CSS, Recharts, Lucide Icons, Dynamic SVG  
**Version:** 1.2.0  

---

## 1. Design Philosophy & Aesthetic Principles

In critical infrastructure and defense operations, a Security Operations Center (SOC) dashboard is not merely a reporting tool—it is a **mission-critical cognitive instrument**. When an alert fires in an air-gapped facility, operators have seconds to determine whether a physical safety system, power generator, or turbine needs to be isolated.

### Core Visual Principles:
1. **Instantaneous Cognitive Triage:** Critical anomalies must draw the eye within 100 milliseconds using high-contrast color psychology (Electric Cyan, Pulsing Rose, Warning Amber).
2. **Dual-Audience Ergonomics:** The interface provides immediate high-level plain-English analogies for operational plant supervisors while granting single-click access to raw mathematical telemetry and cryptographic hashes for Tier-3 forensic analysts.
3. **Hardware State Realism:** The UI reinforces the physical reality of the unidirectional data diode—highlighting the active optical transmit/receive state and hardware return-path severance.
4. **Performance Without Bloat:** Real-time 60 FPS animation rendered using lightweight SVG and pure CSS transitions without heavy 3D WebGL engine dependencies.

---

## 2. Color System & Design Tokens

```
+--------------------------------------------------------------------------------+
| Primary Background:     Deep Obsidian (#030712 / slate-950)                    |
| Surface Card:           Translucent Slate (#0b0f19 / 80% opacity)              |
| Border Accent:          Subtle Cyan Glow (border-cyan-500/20 / slate-800)      |
+--------------------------------------------------------------------------------+
| Primary Cyan Accent:    #06b6d4 (Cyan-500)   -> System Telemetry & Healthy Link|
| Secondary Indigo:       #6366f1 (Indigo-500) -> Data Flow & Neural Analytics   |
| Threat Critical Rose:   #f43f5e (Rose-500)   -> High Severity Threat Spikes    |
| Warning Amber:          #f59e0b (Amber-500)  -> Anomaly Caution & Scanners     |
| Success Emerald:        #10b981 (Emerald-500)-> Safe Verification & Clean Flow |
+--------------------------------------------------------------------------------+
```

### 2.1 CSS Utility Classes & Glassmorphism Tokens
Configured in `dashboard/src/index.css`:

```css
/* Glassmorphism Panel Tokens */
.cyber-card {
  background: rgba(11, 15, 25, 0.85);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(6, 182, 212, 0.18);
  box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.6), 0 0 15px -3px rgba(6, 182, 212, 0.08);
}

/* Glowing Pulsing Indicators */
.pulse-glow-rose {
  box-shadow: 0 0 15px rgba(244, 63, 94, 0.6);
  animation: pulse-rose 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.pulse-glow-cyan {
  box-shadow: 0 0 12px rgba(6, 182, 212, 0.5);
  animation: pulse-cyan 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
```

### 2.2 Typography Hierarchy
- **Telemetry & Monospaced Digits:** `font-mono` (JetBrains Mono / Consolas) for IP addresses, port numbers, JA3 hashes, Shannon entropy floats, and packets-per-second tickers.
- **Headings & Body UI:** `font-sans` (Inter / system-ui) with tight tracking and medium-to-bold weights for rapid legibility under dim SOC ambient lighting.

---

## 3. UI Component Architecture & Wireframe

```
+-------------------------------------------------------------------------------+
| [HEADER] Antigravity SOC | Diode: ACTIVE (1-Way) | Auto-Detect: [ON] | [Guide]|
+-------------------------------------------------------------------------------+
| [WELCOME BANNER] What is this system doing? Simple 3-step guide & analogy     |
+-------------------------------------------------------------------------------+
| [SUMMARY CARDS]                                                               |
|  [ Ingest Throughput ] [ Total Alerts Raised ] [ Highest Confidence ] [Latency]
|     12.4 kpps / 48Mbps         24 Threats              98.4%             8.2 ms
+-------------------------------------------------------------------------------+
| [MANUAL TARGET INSPECTOR]                                                     |
|  [ Tabs: Target IP | Website / URL | Email Address | Phone Number / SMS ]     |
|  [ Input Field + "Deep Inspect" Button ]                                      |
|  [ Real-Time Verdict Card | Forensic RFC Data | Plain-English Kid Analogy ]   |
+-------------------------------------------------------------------------------+
| [SIMULATION ATTACK BAR]                                                       |
|  [ DDoS Flood ] [ C2 Beacon ] [ DGA DNS ] [ TLS Malware ] [ Scan ] [ Exfil ]  |
+-------------------------------------------------------------------------------+
| [REAL-TIME THROUGHPUT & THREAT SPIKE CHART]                                   |
|  (Recharts Multi-Axis Line/Area showing PPS, BPS, and Alert Injections)       |
+-------------------------------------------------------------------------------+
| [NETWORK TOPOLOGY GRAPH]                                                      |
|  (Dynamic SVG Node-Link Graph: Workstations -> Diode -> Internet Targets)     |
+-------------------------------------------------------------------------------+
| [CHRONOLOGICAL ALERT FEED]                                                    |
|  - ALT-29E9FF71 | 22:45:00Z | Data Exfiltration | Conf: 96% | [Inspect Modal] |
|  - ALT-9B14A2C0 | 22:44:12Z | Botnet C2 Beacon  | Conf: 89% | [Inspect Modal] |
+-------------------------------------------------------------------------------+
| [MODAL OVERLAY] Forensic Evidence & Deep Technical Telemetry Inspector        |
+-------------------------------------------------------------------------------+
```

---

## 4. Component Specifications

### 4.1 Header (`dashboard/src/components/Header.jsx`)
- **Visual Features:** Translucent navigation bar with integrated system status.
- **Controls:**
  - Data Diode Status Badge with pulsing green laser beacon.
  - Real-time Alert Counter Badge.
  - Auto-Detection Toggle Switch (pauses/resumes engine processing).
  - Clear Alerts Button.
  - "How It Works" Beginner Guide modal trigger.

### 4.2 Summary Cards (`dashboard/src/components/SummaryCards.jsx`)
- **Metric 1: Network Ingestion Rate:** Displays live Packets Per Second (pps) and computed Kilobits/Megabits Per Second (bps).
- **Metric 2: Threats Detected:** Cumulative count of unique alerts raised during the session.
- **Metric 3: Peak Confidence Gauge:** Percentage confidence of the highest-severity threat in the window.
- **Metric 4: Detection Latency:** Real-time processing duration benchmark ($\le 12\text{ ms}$).

### 4.3 Multi-Vector Manual Inspection Panel (`dashboard/src/components/ManualInspectionPanel.jsx`)
Empowers analysts to interactively evaluate suspicious targets:
1. **IP Address Tab:** Resolves LAN subnets (`192.168.x.x`), enterprise subnets (`10.x.x.x`), and matches against known C2 threat intelligence (Cobalt Strike, Tor exit nodes, Mirai scanners).
2. **Website / URL Tab:** Identifies typosquatting, brand spoofing (e.g., `microsoft-support-fix.xyz`), and computes lexical Shannon entropy.
3. **Email Address Tab:** Flags disposable email providers (`mailinator.com`, `tempmail.com`), typosquatting domains, and free webmail impersonation.
4. **Phone / SMS Tab:** Identifies Wangiri international one-ring toll fraud (+232 Sierra Leone, +247 Ascension Island), tech support scam toll-free lines (1-800, 1-888), and bank smishing shortcodes.
5. **Verdict Layout:** Features color-coded CRITICAL/CLEAN status, real-world historical attack incident dossiers, and plain-English kid analogies.

### 4.4 Simulation Control Bar (`dashboard/src/components/SimulationControl.jsx`)
- Six dedicated, styled trigger buttons representing each threat category:
  - `Volumetric DDoS`: Simulates high-rate SYN flood burst.
  - `C2 Beaconing`: Injects periodic outbound heartbeat flow sequence.
  - `DGA / DNS Tunnel`: Transmits high-entropy synthetic algorithmic domain requests.
  - `TLS Malware`: Sends TLS sessions matching known Cobalt Strike JA3 fingerprints.
  - `Port Recon Scan`: Triggers single-source multi-port/multi-host probes.
  - `Data Exfiltration`: Simulates high outbound asymmetric byte transfer.

### 4.5 Throughput & Threat Spike Chart (`dashboard/src/components/ThroughputChart.jsx`)
- Powered by `recharts`.
- Dual Y-axis visualization:
  - Left Y-Axis: Traffic throughput in Packets per Second (pps) and Kbps.
  - Right Y-Axis: Red alert pulse markers visualizing threat injection spikes.
- Bounded 25-tick sliding window prevents browser memory degradation.

### 4.6 Dynamic SVG Network Topology Graph (`dashboard/src/components/NetworkTopologyGraph.jsx`)
- Declarative SVG node-link visualization:
  - Left Nodes: Monitored Internal Network Clients (Workstations, SCADA PLCs).
  - Center Node: The Physical Data Diode (Unidirectional Gateway with directional arrows).
  - Right Nodes: External Destinations (DNS Servers, Cloud CDNs, Flagged Malicious C2 IPs).
- Active threats trigger glowing animated red pulse rings around compromised nodes with connecting threat lines.

### 4.7 Alert Feed & Forensic Details Modal (`AlertFeed.jsx` & `ThreatDetailsModal.jsx`)
- **Feed:** Sortable chronological list with confidence badges, threat tags, and timestamp.
- **Modal:** Deep-dive modal showing:
  - Standardized JSON payload (copy to clipboard).
  - 5-tuple flow breakdown (Src/Dst IP, Ports, Protocol).
  - Technical mathematical evidence (Shannon entropy score, IAT CV, JA3 hash, NetworkX out-degree).
  - "Plain English / Kid-Friendly" toggle explanation card.
