"""Live smoke test for the running backend.

Exercises the real HTTP + WebSocket surface (not TestClient): health, stats, the
threat-intel feed, the copilot chat contract, attack-scenario injection, the collector
stream endpoint (valid + malformed events) and live WebSocket telemetry.

Usage — start the backend first, then run:

    .\\venv\\Scripts\\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
    .\\venv\\Scripts\\python.exe scripts\\smoke_test.py

Exits 0 when every check passes, 1 otherwise.
"""
import asyncio
import json
import sys
import time

import httpx
import websockets

BASE = "http://127.0.0.1:8000"
WS = "ws://127.0.0.1:8000/ws/alerts"
failures = []


def check(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}{(' — ' + str(detail)) if detail else ''}")
    if not ok:
        failures.append(label)


def wait_for_health(client, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if client.get(f"{BASE}/api/health", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


with httpx.Client() as client:
    check("server reachable (/api/health)", wait_for_health(client))

    health = client.get(f"{BASE}/api/health", timeout=10).json()
    check("health payload", health.get("status") == "healthy", health.get("diode_mode"))

    stats = client.get(f"{BASE}/api/stats", timeout=10).json()
    check("stats has throughput + window", "throughput" in stats and "window_size_seconds" in stats,
          f"pps={stats['throughput']['pps']} alerts={stats['total_alerts_raised']}")

    feed = client.get(f"{BASE}/api/ingest/feed/status", timeout=30).json()
    check("feed status reports the allowlisted adapter",
          feed.get("available") is True and feed.get("indicator_count", 0) > 0,
          f"hosts={feed.get('feed_hosts')} indicators={feed.get('indicator_count')} severity={feed.get('by_severity')}")

    chat = client.post(f"{BASE}/api/copilot/chat", json={"message": "Summarize threat posture"}, timeout=60).json()
    check("copilot chat contract",
          set(chat) >= {"response", "mode", "suggestions"} and bool(chat.get("response")),
          f"mode={chat.get('mode')} suggestions={len(chat.get('suggestions') or [])}")

    sim = client.post(f"{BASE}/api/simulate/c2_beacon", timeout=30).json()
    check("attack scenario injected", sim.get("alerts_raised", 0) >= 1,
          f"flows={sim.get('flows_processed')} alerts={sim.get('alerts_raised')}")

    stream = client.post(f"{BASE}/api/ingest/stream", json={
        "source": "smoke",
        "events": [
            {"timestamp": time.time(), "src_ip": "192.168.10.77", "src_port": 51000,
             "dst_ip": "91.215.102.14", "dst_port": 8443, "bytes": 4096, "packet_count": 4, "entropy": 7.1},
            {"timestamp": time.time(), "src_ip": "not-an-ip", "dst_ip": "91.215.102.14"},
        ],
    }, timeout=30).json()
    check("collector batch accepted valid / rejected junk",
          stream.get("accepted") == 1 and stream.get("rejected") == 1,
          f"accepted={stream.get('accepted')} rejected={stream.get('rejected')} dupes={stream.get('duplicates')} alerts={stream.get('alerts_raised')}")

    alerts = client.get(f"{BASE}/api/alerts", timeout=10).json()
    check("alerts logged", alerts.get("count", 0) >= 1, f"count={alerts.get('count')}")


async def ws_probe():
    seen = []
    async with websockets.connect(WS) as ws:
        started = time.time()
        while len(seen) < 6 and time.time() - started < 15:
            raw = json.loads(await asyncio.wait_for(ws.recv(), timeout=15))
            seen.append(raw.get("type"))
            if raw.get("type") == "telemetry":
                print("      telemetry sample:", json.dumps({
                    "pps": raw.get("data", {}).get("pps"),
                    "bps": raw.get("data", {}).get("bps"),
                    "total_alerts": raw.get("total_alerts"),
                }))
    return seen


try:
    seen = asyncio.run(ws_probe())
    check("websocket streams (snapshot + live telemetry)",
          seen[0] == "snapshot" and "telemetry" in seen, f"types={seen}")
except Exception as exc:  # noqa: BLE001
    check("websocket streams", False, repr(exc))

print("\nRESULT:", "ALL PASS" if not failures else f"{len(failures)} FAILED: {failures}")
sys.exit(1 if failures else 0)
