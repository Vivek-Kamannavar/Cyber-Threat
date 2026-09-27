# Clean SOC Interface, Live Ingestion & AI Chatbot Implementation Plan

- **Branch:** `feat/clean-ui-adapter-ai`
- **Target Model:** GLM 5.3 Flash (or Subagents / Fast Inference)
- **Status:** Ready for execution

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Overhaul the Cyber Threat SOC interface to eliminate visual clutter/AI-slop colors, integrate the `@shrinivas-sn/adapter-ingestion` package for live internet threat feeds, implement a conversational AI security analyst chatbot, and expand the test suite with robust failure-detection test cases.

**Architecture:** 
- **Frontend:** React 19 + Tailwind CSS 4 with a unified 3-pillar navigation (Live Monitor, AI Security Analyst Chat, Data Ingestion Hub) using a deep slate/obsidian palette (`#090d16` / `#0f172a`) and strict semantic alert colors (Red for Critical, Amber for Warning, Muted Slate for Normal).
- **Ingestion:** Python/Node bridge executing `@shrinivas-sn/adapter-ingestion` (`E:\adapter-ingestion`) to stream and normalize real network threat intelligence into `window_manager.py`.
- **AI Chatbot:** FastAPI `/api/copilot/chat` endpoint powered by Groq Llama 3 with real-time sliding window context injection and deterministic offline fallbacks.
- **Test Suite:** Pytest matrix covering concurrency locks, Shannon entropy edge cases, malformed stream recovery, and AI fallback resilience.

**Tech Stack:** React 19, Tailwind CSS 4, Lucide Icons, Recharts, Python 3.13, FastAPI, WebSockets, Groq Llama 3.3/3.1, `@shrinivas-sn/adapter-ingestion`, Pytest.

---

## Global Constraints
- **Active Branch:** All work must be implemented and committed on branch `feat/clean-ui-adapter-ai`.
- Do not break existing sliding window calculation or database persistence logic.
- Keep the dark UI professional and compliant with high-conviction design principles (no random neon glow or rainbow badges).
- Ingestion must gracefully handle network disconnects and malformed data without crashing the FastAPI backend.
- Test pass rate must remain at 100% across all pytest tests.

---

## Task Decomposition

### Task 1: UI Palette & 3-Pillar Navigation Overhaul
**Branch:** `feat/clean-ui-adapter-ai`  
**Files:**
- Modify: `dashboard/src/components/Header.jsx`
- Modify: `dashboard/src/App.jsx`
- Modify: `dashboard/src/pages/LiveMonitorPage.jsx`
- Modify: `dashboard/src/components/AlertFeed.jsx`
- Modify: `dashboard/src/components/SummaryCards.jsx`

**Interfaces:**
- Consumes: `activeTab`, `alerts`, `telemetry`, `connectionMode`
- Produces: Clean 3-tab layout: `monitor` (Live Monitor), `chat` (AI Analyst Chat), `ingest` (Data Ingestion Hub)

- [ ] **Step 1: Simplify Header and Global Status Banner**
  Replace cluttered header buttons with a clean top bar containing: Project Title, Diode Status Badge, Stream Source Selector, and Clean Settings Cog.
- [ ] **Step 2: Clean up Color Tokens in Tailwind**
  Strip neon glow and rainbow badges; use `#090d16` background, `#0f172a` cards, `#1e293b` borders, and Electric Cobalt accents.
- [ ] **Step 3: Refactor AlertFeed and SummaryCards**
  Present key KPIs (Throughput PPS/BPS, Window Anomaly Score, Active Incidents) in clean cards with progressive disclosure for deep packet details.
- [ ] **Step 4: Verify Frontend Build**
  Run: `npm run build --prefix dashboard`

---

### Task 2: Conversational AI Security Analyst Chatbot
**Branch:** `feat/clean-ui-adapter-ai`  
**Files:**
- Modify: `backend/copilot.py`
- Modify: `backend/main.py`
- Create: `dashboard/src/components/AiChatbotPanel.jsx`
- Modify: `dashboard/src/services/apiService.js`
- Test: `tests/test_copilot_chat.py`

**Interfaces:**
- Consumes: Current telemetry snapshot, active alert payload, user prompt
- Produces: Streaming/Async JSON `{ response: str, mode: "GROQ" | "OFFLINE_HEURISTIC", suggestions: list[str] }`

- [ ] **Step 1: Write failing test for Copilot Chat endpoint**
  Create `tests/test_copilot_chat.py` testing `/api/copilot/chat` with valid prompts, empty context, and offline fallback.
- [ ] **Step 2: Implement `/api/copilot/chat` in `backend/copilot.py` and `backend/main.py`**
  Add context-aware conversational prompt builder injecting active alerts, sliding window telemetry, and facility status.
- [ ] **Step 3: Build `AiChatbotPanel.jsx` in Dashboard**
  Create interactive chat interface with markdown rendering, one-click quick action chips (*"Summarize Threat Posture"*, *"Generate Firewall Rules"*, *"Explain Incident #1"*).
- [ ] **Step 4: Run Copilot Tests**
  Run: `.\venv\Scripts\python.exe -m pytest tests/test_copilot_chat.py`

---

### Task 3: Live Internet Ingestion Bridge (`adapter-ingestion`)
**Branch:** `feat/clean-ui-adapter-ai`  
**Files:**
- Create: `ingest/adapter_bridge.py`
- Modify: `backend/main.py`
- Create: `dashboard/src/pages/IngestionHubPage.jsx`
- Modify: `dashboard/src/App.jsx`
- Test: `tests/test_adapter_bridge.py`

**Interfaces:**
- Consumes: Data streams from `E:\adapter-ingestion` or public threat intelligence feeds
- Produces: Normalized packet events `{ timestamp, src_ip, dst_ip, bytes, entropy, flags }` sent to `window_manager`

- [ ] **Step 1: Write failing test for adapter bridge normalizer**
  Create `tests/test_adapter_bridge.py` verifying packet normalization, deduplication, and anomaly window injection.
- [ ] **Step 2: Implement Ingestion Bridge & Endpoint**
  Add `/api/ingest/stream` batch receiver in `backend/main.py` and Python bridge executing ingestion pipelines.
- [ ] **Step 3: Build Ingestion Hub UI in Dashboard**
  Create `IngestionHubPage.jsx` showing Live Internet Stream status, PCAP file upload dropzone, and attack scenario injector.
- [ ] **Step 4: Run Ingestion Bridge Tests**
  Run: `.\venv\Scripts\python.exe -m pytest tests/test_adapter_bridge.py`

---

### Task 4: Robust Failure & Concurrency Test Matrix
**Branch:** `feat/clean-ui-adapter-ai`  
**Files:**
- Create: `tests/test_robustness.py`
- Test: `tests/test_robustness.py`

**Interfaces:**
- Tests all 6 critical edge cases from the test matrix:
  1. Concurrency burst (100 simultaneous packets).
  2. Shannon entropy math stability (zero-byte / single-byte payloads).
  3. Corrupted packet recovery.
  4. Offline AI fallback when API keys are absent.
  5. SQLite concurrent write safety.
  6. WebSocket broadcast reconnect resilience.

- [ ] **Step 1: Write robustness test suite in `tests/test_robustness.py`**
- [ ] **Step 2: Execute full test suite**
  Run: `.\venv\Scripts\python.exe -m pytest tests/`
- [ ] **Step 3: Run dashboard production build check**
  Run: `npm run build --prefix dashboard`
