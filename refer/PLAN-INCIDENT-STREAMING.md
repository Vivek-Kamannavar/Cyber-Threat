# Continuous Incident Streaming & Full Threat Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore continuous real-time SOC threat incident streaming across both live FastAPI backend and client-side simulation modes, and pre-populate a realistic 6-threat-class baseline upon startup.

**Architecture:** 
1. Pre-load a rich, realistic 6-vector threat baseline (`Botnet C2`, `DGA DNS`, `SYN DDoS`, `Encrypted Malware`, `Port Scan`, `Data Exfiltration`) in both `dashboard/src/services/apiService.js` and `backend/main.py` so the incident stream immediately displays rich SOC data on startup.
2. Implement autonomous periodic threat injection in the background simulation loops (`backend/main.py` background worker and `apiService.js` cloud simulator) that periodically streams realistic threat scenarios when auto-detection is enabled, steadily updating the live incident stream count and feed in real-time.
3. Preserve zero false positives on pure benign traffic, maintain full compatibility with all manual simulations, file uploads, AI copilot, deep dives, clear alerts, and automated test suites.

**Tech Stack:** FastAPI, Python 3.13, WebSockets, React 19, Vite, Tailwind CSS, Pytest.

---

## Tasks

### Task 1: Expand Baseline Incidents in Frontend & Backend

**Files:**
- Modify: `dashboard/src/services/apiService.js:65-115`
- Modify: `backend/main.py:48-80`

- [ ] **Step 1: Update `INITIAL_DEMO_ALERTS` in `apiService.js` with all 6 threat vectors**
- [ ] **Step 2: Add `BASELINE_DEMO_ALERTS` and `_ensure_baseline_alerts()` in `backend/main.py`**
- [ ] **Step 3: Verify initial state in both modes**

### Task 2: Implement Autonomous Periodic Threat Streaming Loops

**Files:**
- Modify: `dashboard/src/services/apiService.js:307-345`
- Modify: `backend/main.py:80-125`

- [ ] **Step 1: Add periodic threat scenario generation to `background_flow_simulation()` in `backend/main.py`**
- [ ] **Step 2: Add periodic synthetic threat generation to `startCloudSimulation()` in `dashboard/src/services/apiService.js`**
- [ ] **Step 3: Guard with `auto_detection_enabled` so toggling detection off stops threat generation**

### Task 3: Automated Testing & Verification

**Files:**
- Create: `tests/test_incident_streaming.py`
- Run: `pytest` across all test suites
- Run: `npm run build --prefix dashboard`

- [ ] **Step 1: Create `tests/test_incident_streaming.py` testing baseline completeness and periodic generation**
- [ ] **Step 2: Run pytest suite (all 69+ tests)**
- [ ] **Step 3: Run Vite frontend build**
- [ ] **Step 4: Commit changes to `feat/continuous-incident-streaming-soc`**
