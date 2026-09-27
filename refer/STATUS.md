# Project Status: Cyber-Threat Detection

- **Current Branch:** `feat/clean-ui-adapter-ai` (clean UI adapter + AI analyst work)
- **Location:** `E:\Cyber-Threat`
- **Active Ports / Services:**
  - Backend API & WebSockets: `http://127.0.0.1:8000`
  - SOC Dashboard: `http://127.0.0.1:5173` (also deployed to Firebase)
- **Current Milestone:** Clean SOC interface, conversational AI analyst, and internet ingestion bridge implemented

---

## Completed Architecture & Capabilities
1. **Thread-Safe Detection Engine:** `asyncio.Lock` sliding window manager (`engine/window_manager.py`) with dynamic threshold config.
2. **Persistent Storage:** SQLite persistence (`backend/database.py`) for alerts, metrics, and forensic audit logs.
3. **Multi-Source Ingestion:** Scapy PCAP replay and Zeek/Bro log ingestion pipeline (`ingest/`) with `/api/upload` endpoint.
4. **Groq AI Copilot:** Llama 3.3/3.1 threat reasoning engine (`backend/services/groq_service.py`) providing automated incident containment advice.
5. **Conversational AI Analyst:** `backend/copilot.py` + `POST /api/copilot/chat` inject the live telemetry snapshot and newest alerts into every prompt, returning `{response, mode, suggestions}` and degrading to deterministic offline heuristics when no API key is present.
6. **Internet Ingestion Bridge:** `ingest/adapter_bridge.py` drives `@shrinivas-sn/adapter-ingestion` out of band, normalizes stored records into deduplicated indicators in a local cache (`backend/data/threat_intel.json`), and accepts collector packet batches via `POST /api/ingest/stream` (plus `/api/ingest/feed/status` and `/api/ingest/feed/refresh`).
7. **Clean SOC Dashboard:** deep obsidian/cobalt token palette (`dashboard/src/index.css`), three primary pillars (Live Monitor, AI Analyst, Data Ingestion) with Topology Lab and Forensic Scanner as secondary links, real capture replay, scenario injection, and live/mock fallback.
8. **Robustness Matrix:** `tests/` covers concurrency bursts, entropy edge cases, corrupted capture recovery, offline AI fallback, SQLite concurrent writes, and WebSocket reconnect pruning.

---

## Verification
- `.\venv\Scripts\python.exe -m pytest tests/` → **66 passed**
- `npm run build --prefix dashboard` → clean production build
- `npm run lint --prefix dashboard` → 0 errors (25 pre-existing warnings)

---

## Next up (start here)
1. **Full Integration Smoke Test:** Start backend (`python -m uvicorn backend.main:app --reload`) and dashboard (`npm run dev --prefix dashboard`) to verify live WebSocket streaming, the AI Analyst tab, and PCAP upload workflows end to end.
2. **Populate the Threat Feed:** Point `ADAPTER_INGESTION_DIR` at an adapter-ingestion checkout containing real threat-intel adapters, then run **Data Ingestion → Run adapter pipeline** and confirm indicators appear.
3. **Jury Demo & Evaluation:** Review presentation flow using assets in `refer/CyberThreat_Detection_Demo.mp4` and `refer/Cyber_Threat_Detection_Whitepaper.html`.
