# Project Status: Cyber-Threat Detection

- **Current Branch:** `main` (synced to `origin/main` at commit `5549109`)
- **Location:** `E:\Cyber-Threat`
- **Active Ports / Services:**
  - Backend API & WebSockets: `http://127.0.0.1:8000`
  - SOC Dashboard: `http://127.0.0.1:5173` (also deployed to Firebase)
- **Current Milestone:** Production Ready, Deployed, & Reorganized for Jury Verification

---

## Completed Architecture & Capabilities
1. **Thread-Safe Detection Engine:** `asyncio.Lock` sliding window manager (`backend/engine/window_manager.py`) with dynamic threshold config.
2. **Persistent Storage:** SQLite persistence (`backend/database.py`) for alerts, metrics, and forensic audit logs.
3. **Multi-Source Ingestion:** Scapy PCAP replay and Zeek/Bro log ingestion pipeline (`ingest/`) with `/api/upload` endpoint.
4. **Groq AI Copilot:** Llama 3.3/3.1 threat reasoning engine (`backend/copilot.py`) providing automated incident containment advice.
5. **Interactive SOC Dashboard:** React/Tailwind frontend featuring Live Monitor, Topology Lab, Forensic Scanner, and Backend Settings with live/mock fallback.
6. **Project Packaging:** Docs, whitepapers, demo video, and research assets organized in `refer/` with Firebase hosting config (`firebase.json`).

---

## Next up (start here)
1. **Full Integration Smoke Test:** Start backend (`python -m uvicorn backend.main:app --reload`) and dashboard (`npm run dev --prefix dashboard`) to verify live WebSocket streaming and PCAP upload workflows.
2. **Run Test Suite:** Execute `pytest` across `tests/` to validate engine, database, copilot, and ingest modules.
3. **Jury Demo & Evaluation:** Review presentation flow using assets in `refer/CyberThreat_Detection_Demo.mp4` and `refer/Cyber_Threat_Detection_Whitepaper.html`.
