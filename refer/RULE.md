# Operational Rules & Engineering Standards (RULE.md)

**Project:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Enforcement Level:** Mandatory for all contributors and automated agents  
**Scope:** Architecture, Security, Python Backend, React Frontend, and Ingestion Pipeline  

---

## 1. Core Physical & Hardware Diode Invariants (NON-NEGOTIABLE)

1. **Zero Outbound Transmission Guarantee (Rule 1.1):**
   - Under no circumstances shall the software open a socket or emit a packet onto the monitored network interface.
   - The system must never send TCP RST, TCP ACK, ICMP unreachable, or inline blocking packets.
   - Any proposed feature that requires active network probing, ARP querying, or automated firewall rule injection on the monitored network is **strictly rejected**.
2. **Offline / Passive Threat Intelligence Rule (Rule 1.2):**
   - Threat intelligence lookups (IP reputations, malicious JA3 signatures, known malicious subnets, phone fraud lists) must be conducted using **local, in-memory, air-gapped databases**.
   - No external live HTTP queries (e.g., to VirusTotal, AbuseIPDB, or Shodan) may be made from the air-gapped detection enclave.
3. **No Payload Decryption Rule (Rule 1.3):**
   - The system shall never attempt TLS man-in-the-middle (MitM) decryption, certificate spoofing, or payload inspection.
   - All encrypted traffic inspection must rely strictly on metadata: Layer 3/4 headers, packet arrival timing, byte counts, TLS Client Hello SNI, and JA3/JA4 cryptographic fingerprints.

---

## 2. Memory & Real-Time Performance Constraints

1. **Bounded State Invariant (Rule 2.1):**
   - No data structure within the engine may grow unbounded over time.
   - The sliding window buffer must enforce strict eviction policies ($W = 60.0\text{ seconds}$).
   - Any secondary indexing tables (e.g., `src_ip_index`) must be pruned concurrently with the main flow deque.
   - Frontend telemetry charts must cap time-series histories to the latest 25 data points.
2. **Bounded Latency Rule (Rule 2.2):**
   - Mathematical calculations (entropy, inter-arrival time statistics, graph traversal) must execute in $\le 12\text{ ms}$ per 60-second window tick.
   - Expensive algorithms with $O(V^3)$ or higher time complexity are prohibited in the hot ingestion loop.
3. **Alert Deduplication & Cooldown Rule (Rule 2.3):**
   - To avoid alert fatigue and memory exhaustion during continuous flood attacks, the engine must enforce a minimum **3.0-second cooldown** per `(threat_class, entity_id)` tuple.

---

## 3. Python Backend Engineering Standards

1. **Language & Type Safety (Rule 3.1):**
   - Target Python version: **Python 3.10+**.
   - All function signatures must include explicit type hints (`typing.List`, `typing.Dict`, `typing.Optional`, `typing.Tuple`, `typing.Any`).
   - Pydantic models must be used for all REST API request and response bodies.
2. **Asynchronous Concurrency (Rule 3.2):**
   - FastAPI route handlers interacting with the WebSocket manager must be `async def`.
   - The background traffic generator and telemetry loop must run as a managed `asyncio.create_task` that sleeps cooperatively (`asyncio.sleep(0.5)`).
   - Global mutable state (e.g., `auto_detection_enabled`) must be modified predictably and broadcast to all active WebSocket listeners immediately.
3. **Standardized Alert Schema Compliance (Rule 3.3):**
   - Every alert raised by any engine module must adhere to the standardized schema:
     ```json
     {
       "alert_id": "ALT-XXXXXXXX",
       "timestamp": "YYYY-MM-DDTHH:MM:SSZ",
       "flow_identifier": {
         "src_ip": "string",
         "src_port": 0,
         "dst_ip": "string",
         "dst_port": 0,
         "protocol": "TCP|UDP|ICMP"
       },
       "threat_class": "string",
       "confidence_score": 0.00,
       "supporting_evidence_feature": {
         "technical_reason": "string",
         "reason": "Plain English kid-friendly analogy"
       }
     }
     ```
4. **Error Handling & Resilience (Rule 3.4):**
   - Ingestion parsers must catch malformed packets or truncated log lines gracefully without terminating the application process.

---

## 4. Frontend & SOC UI Standards

1. **Component Architecture (Rule 4.1):**
   - Built with React 18 functional components and standard hooks (`useState`, `useEffect`, `useRef`).
   - Components must be decoupled, modular, and placed in `dashboard/src/components/`.
2. **Resilient WebSocket Lifecycle (Rule 4.2):**
   - The WebSocket connection must implement automated reconnection with a 3000ms backoff interval if the server restarts.
   - Active WebSocket instances must be cleanly closed during component unmounting to prevent memory leaks.
3. **Aesthetic & Design Tokens (Rule 4.3):**
   - Adhere to the Mission-Critical SOC Cyber-Command palette:
     - Background: Deep Obsidian / Slate 950 (`#030712`, `#020617`).
     - Accent Primary: Electric Cyan (`#06b6d4`).
     - Secondary: Indigo (`#6366f1`).
     - Threat Critical: Vivid Rose (`#f43f5e`).
     - Warning: Amber (`#f59e0b`).
     - Safe / Healthy: Emerald (`#10b981`).
   - Borders must use subtle translucent glassmorphic styling (`border-slate-800` / `border-cyan-500/30`).
4. **Dual-Audience Communication Rule (Rule 4.4):**
   - Every threat presentation must be accessible to both Tier-3 security engineers and non-technical decision makers.
   - The UI must prominently offer plain-English, kid-friendly explanations alongside raw technical telemetry.

---

## 5. Security & Input Sanitization Standards

1. **Input Validation (Rule 5.1):**
   - The manual target inspector (`/api/inspect`) must sanitize and validate all inputs:
     - IP addresses: Validated against IPv4/IPv6 address regex.
     - Domains: Stripped of protocol prefixes (`http://`, `https://`) and trailing slashes.
     - Emails: Validated against standard user/domain RFC formats.
     - Phone numbers: Stripped of non-digit characters except the leading `+`.
2. **No Hardcoded Secrets (Rule 5.2):**
   - No private keys, passwords, or sensitive network tokens may be committed to version control.
3. **Air-Gap Operational Security (Rule 5.3):**
   - Never log sensitive payload contents.
   - Ensure all output logs are compatible with syslog or SIEM collectors over secure local sockets.
