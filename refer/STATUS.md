# Project Status: Cyber-Threat Detection

- **Current Branch:** `feat/clean-ui-adapter-ai`
- **Location:** `E:\Cyber-Threat`
- **Active Ports:** Backend `8000` | Dashboard `5173` (also deployed to Firebase)
- **Current Milestone:** Clean SOC interface, conversational AI analyst, and verified live threat-intel feed

---

## Current State & Capabilities
1. **Clean SOC Interface:** Unified 3-pillar navigation (Live Monitor, AI Security Analyst Chat, Data Ingestion Hub) using deep obsidian/cobalt palette (`dashboard/src/index.css`).
2. **Conversational AI Analyst:** `/api/copilot/chat` endpoint powered by Groq Llama 3 with real-time sliding window context injection and deterministic offline fallbacks.
3. **Live Threat-Intel Bridge:** `ingest/adapter_bridge.py` feeds 100 live GitHub security advisories into local cache (`backend/data/threat_intel.json`).
4. **Verification Matrix:** 68/68 pytest suite passing, `npm run build --prefix dashboard` clean, live smoke test passing.

---

## Next up (start here)
1. **Launch Stack:** Run `uvicorn backend.main:app` and `npm run dev --prefix dashboard` to visually review the 3 pillars in the browser.
2. **Jury Evaluation & Demo:** Review demo presentation flow using assets in `refer/CyberThreat_Detection_Demo.mp4` and `refer/Cyber_Threat_Detection_Whitepaper.html`.
