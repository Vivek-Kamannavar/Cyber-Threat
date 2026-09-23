# Project Memory & Architectural Knowledge Base (MEMORY.md)

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Purpose:** Persistent technical context, Architectural Decision Records (ADRs), institutional learnings, and operational gotchas for engineers and AI agents working on this codebase.  
**Last Updated:** 2026-09-20  

---

## 1. Architectural Decision Records (ADRs)

### ADR-001: Metadata-Only Inspection vs. TLS Man-in-the-Middle Decryption
- **Context:** Over 85% of contemporary network traffic is encrypted via TLS 1.3 or QUIC. Traditional security appliances attempt to terminate SSL sessions, inspect payloads, and re-encrypt traffic.
- **Decision:** Strictly prohibit payload decryption and operate exclusively on Layer 3/4 headers, inter-arrival timings, packet byte counters, and unencrypted handshake metadata (SNI, JA3/JA4 MD5 fingerprints, cipher suite vectors).
- **Rationale:** 
  1. In a physical data diode, the return path is physically cut; bidirectional TLS proxying is physically impossible.
  2. Industrial SCADA protocols (e.g., Modbus over TLS) and defense enclaves forbid certificate injection on mission-critical embedded PLCs.
  3. Processing metadata maintains a sub-12ms latency budget, whereas full cryptographic decryption introduces multi-millisecond overhead and substantial CPU bottlenecks.

### ADR-002: In-Memory Ring Buffer Deque vs. Persistent Database in Hot Path
- **Context:** Network traffic in critical infrastructure can spike to $> 15,000$ flows/second. Persisting every single raw flow into PostgreSQL, MongoDB, or SQLite would create massive disk I/O bottlenecks and risk storage exhaustion under volumetric DDoS attacks.
- **Decision:** Utilize an in-memory sliding window state manager backed by Python's `collections.deque` with a fixed time duration ($W = 60.0\text{ seconds}$) and automated $O(1)$ pruning.
- **Rationale:**
  1. High throughput: Memory-only operations run at RAM speeds with zero disk write contention.
  2. Bounded memory: Stale flows older than 60 seconds are immediately evicted, keeping memory footprint $< 120\text{ MB}$ indefinitely.
  3. Threat detection is temporal: Correlating flows over the recent 60-second window is sufficient for high-accuracy threat classification without storing petabytes of historical benign flows.

### ADR-003: Hybrid Dual-Tier Classification vs. Heavy Deep Learning Models
- **Context:** Many modern AI projects apply deep neural networks (CNNs, LSTMs, Transformers) for network anomaly detection.
- **Decision:** Implement a hybrid dual-tier architecture:
  - **Tier 1:** Deterministic, domain-specific heuristic rules for well-understood attack patterns (Entropy, IAT statistics, N-Gram rarity, NetworkX graph fan-out).
  - **Tier 2:** Unsupervised Scikit-Learn Isolation Forest ($100$ trees, $5\%$ contamination) trained on multi-variate flow vectors `[bytes_sent, bytes_received, packet_count, src_port, dst_port]`.
- **Rationale:**
  1. **Determinism & Explainability:** Critical infrastructure operators must know *exactly* why a turbine or gateway was flagged (e.g., "Outbound byte asymmetry ratio was 1475.88", rather than "Neural layer 4 activation was 0.87").
  2. **Latency Guarantee:** Heuristic rules and Isolation Forest score flows in $< 12\text{ ms}$, whereas large neural networks require GPU acceleration and introduce latency variance.
  3. **Zero False-Positive Suppression:** Tier 1 catches known threat classes deterministically, while Tier 2 acts as a safety net for unknown statistical outliers.

### ADR-004: Push-Based WebSocket Streaming vs. Client-Side HTTP Polling
- **Context:** The React SOC dashboard must visualize real-time traffic throughput and display urgent threat alerts without delay.
- **Decision:** Utilize an asynchronous WebSocket channel (`/ws/alerts`) with an asyncio broadcast manager on the FastAPI backend.
- **Rationale:**
  1. Telemetry latency reduced to $< 5\text{ ms}$ upon alert generation.
  2. Eliminates continuous HTTP request/response connection setup overhead.
  3. Allows instantaneous broadcasting to multiple SOC monitoring displays simultaneously.

### ADR-005: Dual-Audience Narrative Model (Technical Forensic + Plain-English Analogy)
- **Context:** Industrial plant managers and control-room operators are often electrical or mechanical engineers, not cyber specialists. Complex jargon like "JA3 MD5 collision" or "Shannon entropy collapse" delays incident response.
- **Decision:** Every alert record and inspection report provides two parallel explanations: a rigorous RFC-level technical forensic description and an intuitive, real-world kid-friendly analogy.
- **Rationale:** Facilitates instant cross-functional alignment between SOC security analysts and operational plant supervisors during high-stress cyber incidents.

---

## 2. Critical Learnings & Technical Gotchas

### 2.1 Alert Flooding & Deduplication Cooldown
- **Issue:** During a simulated DDoS flood or high-rate port scan, the engine could fire thousands of alerts per second for the same attacker IP, saturating WebSocket buffers and freezing the browser DOM.
- **Fix:** Implemented `_should_raise_alert(alert_key, entity, cooldown_seconds=3.0)` in `ThreatDetector`. Alerts with the same threat key and entity IP within 3.0 seconds are suppressed from dispatching while aggregate packet counters continue to update silently.

### 2.2 Recharts Frontend Memory Leak Prevention
- **Issue:** In an operational SOC dashboard running for days, appending telemetry points to state indefinitely causes browser tab memory to balloon to several gigabytes.
- **Fix:** In `dashboard/src/App.jsx`, the telemetry time-series state updater strictly caps the array to the latest 25 elements:
  ```javascript
  setHistoryData((prev) => {
    const updated = [...prev, newPoint];
    return updated.slice(-25);
  });
  ```

### 2.3 NetworkX Graph Traversal Cost
- **Issue:** Building and analyzing a graph with thousands of nodes inside a per-packet hot loop causes CPU spikes.
- **Fix:** The directed graph in `analyze_fanout_networkx()` is only instantiated and analyzed when evaluating the sliding window flows for reconnaissance detection, bounded by the 60-second window flow set.

### 2.4 Browser WebSocket Disconnection Resilience
- **Issue:** When the backend server restarts during development or network maintenance, standard WebSocket instances throw unhandled errors and stop updating.
- **Fix:** `App.jsx` wraps the WebSocket initialization in an automated reconnection loop with a 3000ms backoff interval (`reconnectTimeout = setTimeout(connectWebSocket, 3000)`).

---

## 3. Active Component Registry & Topology

| Component | Path | Responsibilities | Key Dependencies |
| :--- | :--- | :--- | :--- |
| **Ingestion Normalizer** | `ingest/parser.py` | Tails Zeek logs and parses PCAP streams into normalized dicts. | Standard Library |
| **Synthetic Streamer** | `ingest/traffic_generator.py` | Generates realistic background noise and 6 distinct attack vectors. | Standard Library, random |
| **Window State Manager** | `engine/window_manager.py` | Thread-safe 60s sliding window buffer with $O(1)$ deque push & prune. | `collections.deque` |
| **Feature Extraction** | `engine/features.py` | Entropy, IAT stats, DNS n-grams, NetworkX bipartite fanout graph. | `networkx`, `numpy`, `math` |
| **Heuristics Engine** | `engine/models/heuristic_rules.py` | Domain-specific classifiers for 6 primary threat categories. | `engine.features` |
| **Isolation Forest** | `engine/models/isolation_forest.py` | Unsupervised multi-variate statistical flow anomaly detector. | `scikit-learn`, `numpy` |
| **Threat Detector** | `engine/threat_detector.py` | Master detection orchestrator, cooldown cache, alert JSON formatter. | `uuid`, `time` |
| **FastAPI Server** | `backend/main.py` | REST endpoints, WebSocket manager, manual multi-vector inspector. | `fastapi`, `uvicorn`, `pydantic` |
| **React SOC UI** | `dashboard/src/App.jsx` | SOC dashboard state, real-time Recharts, SVG topology graph, alerts. | `react`, `lucide-react`, `recharts` |

---

## 4. Port & Networking Map

- **TCP Port 8000:** FastAPI Application Gateway (REST API + `/ws/alerts` WebSocket).
- **TCP Port 5173:** Vite Development Server (React SOC Dashboard).
- **Diode Monitoring Interface:** Promiscuous RX-only interface (no IP or localhost-bound in test mode).
