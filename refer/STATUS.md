# Project Status: Cyber-Threat Detection

- **Current Branch:** `feat/clean-ui-adapter-ai` (clean UI adapter + AI analyst work)
- **Location:** `E:\Cyber-Threat`
- **Active Ports / Services:**
  - Backend API & WebSockets: `http://127.0.0.1:8000`
  - SOC Dashboard: `http://127.0.0.1:5173` (also deployed to Firebase)
- **Current Milestone:** Clean SOC interface, conversational AI analyst, and a verified live internet threat feed

---

## Completed Architecture & Capabilities
1. **Thread-Safe Detection Engine:** `asyncio.Lock` sliding window manager (`engine/window_manager.py`) with dynamic threshold config.
2. **Persistent Storage:** SQLite persistence (`backend/database.py`) for alerts, metrics, and forensic audit logs.
3. **Multi-Source Ingestion:** Scapy PCAP replay and Zeek/Bro log ingestion pipeline (`ingest/`) with `/api/upload` endpoint.
4. **Groq AI Copilot:** Llama 3.3/3.1 threat reasoning engine (`backend/services/groq_service.py`) providing automated incident containment advice.
5. **Conversational AI Analyst:** `backend/copilot.py` + `POST /api/copilot/chat` inject the live telemetry snapshot and newest alerts into every prompt, returning `{response, mode, suggestions}` and degrading to deterministic offline heuristics when no API key is present.
6. **Internet Ingestion Bridge:** `ingest/adapter_bridge.py` drives `@shrinivas-sn/adapter-ingestion` out of band, normalizes stored records into deduplicated indicators in a local cache (`backend/data/threat_intel.json`, gitignored), and accepts collector packet batches via `POST /api/ingest/stream` (plus `/api/ingest/feed/status` and `/api/ingest/feed/refresh`).
7. **Clean SOC Dashboard:** deep obsidian/cobalt token palette (`dashboard/src/index.css`), three primary pillars (Live Monitor, AI Analyst, Data Ingestion) with Topology Lab and Forensic Scanner as secondary links, real capture replay, scenario injection, and live/mock fallback.
8. **Robustness Matrix:** `tests/` covers concurrency bursts, entropy edge cases, corrupted capture recovery, offline AI fallback, SQLite concurrent writes, and WebSocket reconnect pruning.

---

## Live Feed Source (verified 2026-09-27)

**GitHub Advisory Database** — `https://api.github.com/advisories`

| Check | Result |
| :--- | :--- |
| Access tier | **0** — documented public REST API, no key |
| Shape | bare JSON **array** with a per-record `html_url` deep link (`records_path: "$"`) |
| Licence | **CC-BY 4.0** (legal gate passed; attribution in `fixtures/api.github.com/ATTRIBUTION.md`) |
| UA probe | default UA `200`, **empty UA `403`** — the adapter therefore sets `User-Agent` + `Accept` as required config |
| Fixture verification | `validateAdapter` ok, `verifyAgainstFixtures` **5/5 (ratio 1.0, no field failures)** |
| Canary proof | renamed `source_id` path → `parsed 0`, canary `stale` (min_records + required_field_ratio + staleness breaches) |
| Live run | `fetched 100 / parsed 100 / written 100`, canary `ok` |
| In SOC cache | **100 indicators** — CRITICAL 10, HIGH 54, MEDIUM 34, LOW 2 |

Adapter written to the ingestion package (separate repo `E:\adapter-ingestion`, **not yet committed there**):
`adapters/api.github.com.adapter.json`, `fixtures/api.github.com/{sample-1.json,ATTRIBUTION.md}`,
`scripts/verify-github-advisories-adapter.mjs`.

`AdapterFeedBridge` only consumes adapters on a threat-intel host allowlist (`DEFAULT_FEED_HOSTS` /
`ADAPTER_FEED_HOSTS`, `*` for everything), so the package's unrelated adapters (earthquake, job board)
never appear in the SOC as indicators.

### Sources evaluated and rejected
- **Feodo Tracker (abuse.ch)** — CC0, tier 0, explicit commercial use, real Emotet/QakBot C2 IPs. Not adaptable as the framework stands: `map` rules accept only `path`/`normalize` (no `template`), the record contract's mandatory `url` needs a real per-record URL field and Feodo's JSON has none, and `records_path` is array-only.
- **URLhaus recent JSON** — CC0, tier 0, fresh malware URLs, and `urlhaus_link` would satisfy `url`, but the payload is an object keyed by id (`{"3923855": [ /* … */ ]}`), so `extractAll`'s `rawItems.forEach` cannot walk it.
- Both become usable with a framework `template` map rule or an object-valued `records_path` — a change to `src/`, which the adapter workflow forbids, so it is logged here rather than hacked around.

---

## Verification
- `.\venv\Scripts\python.exe -m pytest tests/` → **68 passed**
- `npm run build --prefix dashboard` → clean production build
- `npm run lint --prefix dashboard` → 0 errors

---

## Next up (start here)
1. **Commit the adapter in the ingestion package:** `E:\adapter-ingestion` is its own git repo; commit the three new files there (adapter, fixture, verify script) so the feed is reproducible.
2. **Full Integration Smoke Test:** start backend (`python -m uvicorn backend.main:app --reload`) and dashboard (`npm run dev --prefix dashboard`), then confirm the Live Monitor WebSocket stream, the AI Analyst tab and the Ingestion Hub feed panel in a browser.
3. **Optional volume upgrade:** add `template` support (or an object-valued `records_path`) to the ingestion framework to unlock the IoC blocklists (Feodo/URLhaus) alongside the advisory feed.
4. **Jury Demo & Evaluation:** review presentation flow using assets in `refer/CyberThreat_Detection_Demo.mp4` and `refer/Cyber_Threat_Detection_Whitepaper.html`.
