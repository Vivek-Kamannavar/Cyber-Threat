# Project Status: Cyber-Threat Detection

- **Current Branch:** `feat/continuous-incident-streaming-soc`
- **Location:** `E:\Cyber-Threat`
- **Active Ports:** Backend `8000` | Dashboard `5173` (also deployed to Firebase)
- **Current Milestone:** Continuous real-time threat incident streaming + 5-minute periodic threat intelligence auto-sync via `@shrinivas-sn/adapter-ingestion`

---

## Current State & Capabilities
1. **Full 6-Vector Threat Baseline:** Pre-loaded with Botnet C2, DGA DNS, SYN DDoS, Encrypted TLS Malware, Recon Scan, and Data Exfiltration across backend & cloud simulation.
2. **Autonomous Incident Streaming:** Background loops in FastAPI and client simulator periodically inject authentic threat scenarios (~every 12-15s) with live WebSocket streaming and 0% false positives on benign traffic.
3. **Automated 5-Minute Threat Intel Sync:** Server-side periodic out-of-band execution via local `@shrinivas-sn/adapter-ingestion` (zero CI latency), live countdown timer, and audit activity stream on Ingestion Hub.
4. **Conversational AI Analyst:** `/api/copilot/chat` endpoint powered by Groq Llama 3 with real-time sliding window context injection and deterministic offline fallbacks.
5. **Verification Matrix:** 72/72 pytest suite passing, `npm run build --prefix dashboard` clean, live smoke and WebSocket tests passing.

---

## Next up (start here)
1. **Launch Stack:** Run `uvicorn backend.main:app` and `npm run dev --prefix dashboard` to inspect the live incident stream and threat intel sync in the browser.
2. **Jury Evaluation & Demo:** Test threat simulations, automated 5m adapter sync countdown, AI copilot deep dives, and PCAP/Zeek file uploads in the Data Ingestion Hub.
