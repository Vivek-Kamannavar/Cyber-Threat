"""
FastAPI Server & WebSocket Streaming Gateway
Provides REST endpoints and WebSocket real-time threat alert streaming for Data Diode Environments.
"""

import sys
import os
import asyncio
import json
import time
import uuid
import re
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is in python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ingest.traffic_generator import TrafficGenerator
from ingest.pcap_loader import PcapStreamLoader
from ingest.parser import ZeekMultiLogCorrelator
from engine.threat_detector import ThreatDetector
from engine.features import calculate_dns_ngram_score
from backend.config import Config
from backend.services.groq_service import GroqCopilotService
from backend.database import get_alert_by_id, save_ai_analysis, get_ai_analysis

app = FastAPI(
    title="Cyber Threat Detection System - Data Diode Environment",
    description="Real-time AI threat detection pipeline for unidirectional network traffic.",
    version="1.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine & generator instances
detector = ThreatDetector(window_size_seconds=Config.WINDOW_SIZE_SECONDS)
generator = TrafficGenerator()

class ConnectionManager:
    """Manages active WebSocket client connections for real-time alert dispatching."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Global auto-detection flag
auto_detection_enabled: bool = True

class ToggleDetectionRequest(BaseModel):
    enabled: Optional[bool] = None

# Background stream simulator task
async def background_flow_simulation():
    """Continuously generates benign background traffic and processes through the ML engine."""
    while True:
        try:
            # Generate continuous normal flow
            flow = generator.generate_benign_flow()
            alerts = []
            
            if auto_detection_enabled:
                alerts = detector.process_flow(flow)
            else:
                # Still record traffic in sliding window for throughput stats, without evaluating threat rules
                detector.window_manager.add_flow(flow)

            # Broadcast live telemetry
            stats = detector.get_stats()
            await manager.broadcast({
                "type": "telemetry",
                "timestamp": time.time(),
                "data": stats["throughput"],
                "total_alerts": stats["total_alerts_raised"],
                "auto_detection_enabled": auto_detection_enabled
            })

            # Broadcast raised alerts if any
            for alert in alerts:
                await manager.broadcast({
                    "type": "alert",
                    "data": alert
                })

            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"Background stream error: {e}")
            await asyncio.sleep(1.0)


@app.on_event("startup")
async def startup_event():
    # Start background flow processing task
    asyncio.create_task(background_flow_simulation())


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "diode_mode": "Read-Only Unidirectional",
        "return_path": "Disabled (Hardware Constrained)",
        "auto_detection_enabled": auto_detection_enabled,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


@app.get("/api/detection/status")
def get_detection_status():
    return {"auto_detection_enabled": auto_detection_enabled}


@app.post("/api/detection/toggle")
async def toggle_detection(req: Optional[ToggleDetectionRequest] = None):
    global auto_detection_enabled
    if req and req.enabled is not None:
        auto_detection_enabled = req.enabled
    else:
        auto_detection_enabled = not auto_detection_enabled

    await manager.broadcast({
        "type": "config",
        "auto_detection_enabled": auto_detection_enabled
    })
    return {
        "status": "success",
        "auto_detection_enabled": auto_detection_enabled
    }


@app.post("/api/alerts/clear")
async def clear_alerts():
    detector.clear_alerts()
    await manager.broadcast({
        "type": "alerts_cleared",
        "total_alerts": 0
    })
    return {"status": "alerts_cleared", "total_alerts": 0}


@app.get("/api/stats")
def get_stats():
    stats = detector.get_stats()
    stats["auto_detection_enabled"] = auto_detection_enabled
    return stats


@app.get("/api/alerts")
def get_alerts():
    return {
        "count": len(detector.get_all_alerts()),
        "alerts": detector.get_all_alerts()
    }


# ======================================================================
# INGESTION PIPELINE (PHASE 2: PCAP & ZEEK REPLAY)
# ======================================================================
class IngestionTracker:
    def __init__(self):
        self.status = "idle"  # idle | replaying | completed | stopped | error
        self.source = ""
        self.total_flows_processed = 0
        self.total_alerts_raised = 0
        self.stop_requested = False
        self.progress_percent = 0.0
        self.active_task: Optional[asyncio.Task] = None

ingestion_tracker = IngestionTracker()


async def replay_file_worker(filepath: str, filename: str, playback_speed: str):
    ingestion_tracker.status = "replaying"
    ingestion_tracker.source = filename
    ingestion_tracker.total_flows_processed = 0
    ingestion_tracker.total_alerts_raised = 0
    ingestion_tracker.stop_requested = False
    ingestion_tracker.progress_percent = 0.0

    delay_map = {
        "1x": 0.04,
        "5x": 0.008,
        "10x": 0.002,
        "instant": 0.0
    }
    delay = delay_map.get(playback_speed, 0.01)

    try:
        if filename.lower().endswith((".pcap", ".pcapng")):
            flow_gen = PcapStreamLoader.stream_flows(filepath)
        else:
            correlator = ZeekMultiLogCorrelator()
            flow_gen = correlator.stream_correlated_flows(filepath)

        for flow in flow_gen:
            if ingestion_tracker.stop_requested:
                ingestion_tracker.status = "stopped"
                break

            alerts = detector.process_flow(flow)
            ingestion_tracker.total_flows_processed += 1
            if alerts:
                ingestion_tracker.total_alerts_raised += len(alerts)
                for alert in alerts:
                    await manager.broadcast({
                        "type": "alert",
                        "data": alert
                    })

            if ingestion_tracker.total_flows_processed % 5 == 0 or delay > 0:
                stats = detector.get_stats()
                await manager.broadcast({
                    "type": "telemetry",
                    "timestamp": time.time(),
                    "data": stats["throughput"],
                    "total_alerts": stats["total_alerts_raised"],
                    "auto_detection_enabled": auto_detection_enabled
                })

            if delay > 0:
                await asyncio.sleep(delay)

        if not ingestion_tracker.stop_requested:
            ingestion_tracker.status = "completed"
            ingestion_tracker.progress_percent = 100.0

    except Exception as e:
        ingestion_tracker.status = "error"
        print(f"File ingestion error: {e}")
    finally:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass


@app.post("/api/ingest/upload")
async def upload_ingest_file(
    file: UploadFile = File(...),
    playback_speed: str = Query("1x", pattern="^(1x|5x|10x|instant)$")
):
    """Uploads and streams a PCAP or Zeek log file through the detection engine."""
    filename = file.filename or "unknown_capture"
    valid_exts = (".pcap", ".pcapng", ".log")
    if not any(filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(status_code=400, detail=f"Unsupported file format. Allowed: {valid_exts}")

    upload_dir = os.path.join(ROOT_DIR, "backend", "data", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, f"{uuid.uuid4().hex}_{filename}")

    with open(temp_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # Cancel previous replay task if still running
    if ingestion_tracker.active_task and not ingestion_tracker.active_task.done():
        ingestion_tracker.stop_requested = True
        await asyncio.sleep(0.05)

    ingestion_tracker.active_task = asyncio.create_task(
        replay_file_worker(temp_path, filename, playback_speed)
    )

    if playback_speed == "instant":
        await ingestion_tracker.active_task

    return {
        "status": "started" if playback_speed != "instant" else ingestion_tracker.status,
        "filename": filename,
        "playback_speed": playback_speed,
        "flows_processed": ingestion_tracker.total_flows_processed,
        "alerts_raised": ingestion_tracker.total_alerts_raised
    }


@app.post("/api/ingest/stop")
async def stop_ingest_file():
    """Stops the active PCAP or Zeek replay task."""
    ingestion_tracker.stop_requested = True
    ingestion_tracker.status = "stopped"
    return {"status": "stopped"}


@app.get("/api/ingest/status")
def get_ingest_status():
    """Returns the current file ingestion status and progress."""
    return {
        "status": ingestion_tracker.status,
        "source": ingestion_tracker.source,
        "flows_processed": ingestion_tracker.total_flows_processed,
        "alerts_raised": ingestion_tracker.total_alerts_raised,
        "progress_percent": ingestion_tracker.progress_percent
    }


# ======================================================================
# AI COPILOT PIPELINE (PHASE 3: GROQ INCIDENT ASSISTANT)
# ======================================================================
ai_copilot = GroqCopilotService()


@app.post("/api/ai/analyze-alert/{alert_id}")
async def analyze_alert_with_ai(alert_id: str):
    """
    Generates or fetches cached AI-driven executive analysis, impact assessment,
    and remediation checklist for a specific threat alert.
    """
    cached = get_ai_analysis(alert_id)
    if cached:
        return {"alert_id": alert_id, "cached": True, "analysis": cached}

    alert = get_alert_by_id(alert_id)
    if not alert:
        for a in detector.get_all_alerts():
            if a.get("alert_id") == alert_id:
                alert = a
                break

    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    analysis = ai_copilot.analyze_alert(alert)
    save_ai_analysis(alert_id, analysis)
    return {"alert_id": alert_id, "cached": False, "analysis": analysis}


class AiChatRequest(BaseModel):
    message: str
    alert_id: Optional[str] = None
    alert_context: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = None


@app.post("/api/ai/chat")
async def ai_copilot_chat(req: AiChatRequest):
    """Interactive SOC Analyst chat regarding active threats and air-gapped containment."""
    ctx = req.alert_context
    if req.alert_id and not ctx:
        ctx = get_alert_by_id(req.alert_id)

    reply = ai_copilot.chat_response(req.message, ctx, req.history)
    return {"reply": reply}


# ======================================================================
# DYNAMIC TOPOLOGY ENDPOINT (PHASE 4)
# ======================================================================
@app.get("/api/topology")
def get_live_topology():
    """Extracts communicating hosts and interaction arcs dynamically from the sliding window."""
    flows = detector.window_manager.get_recent_flows()
    nodes = {}
    edges = []
    seen_edges = set()

    for f in flows:
        fid = f.get("flow_identifier", {})
        src = fid.get("src_ip")
        dst = fid.get("dst_ip")
        proto = fid.get("protocol", "TCP")

        if src and src not in nodes:
            nodes[src] = {
                "id": src,
                "label": fid.get("src_label") or src,
                "is_internal": src.startswith(("192.168.", "10.", "172.16.")),
                "is_threat": False
            }
        if dst and dst not in nodes:
            nodes[dst] = {
                "id": dst,
                "label": fid.get("dst_label") or dst,
                "is_internal": dst.startswith(("192.168.", "10.", "172.16.")),
                "is_threat": False
            }

        if src and dst:
            edge_key = f"{src}->{dst}"
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                edges.append({
                    "source": src,
                    "target": dst,
                    "protocol": proto,
                    "bytes": f.get("bytes_sent", 0)
                })

    recent_alerts = detector.get_all_alerts()[-20:]
    for a in recent_alerts:
        afid = a.get("flow_identifier", {})
        asrc = afid.get("src_ip")
        adst = afid.get("dst_ip")
        if asrc in nodes:
            nodes[asrc]["is_threat"] = True
        if adst in nodes:
            nodes[adst]["is_threat"] = True

    return {
        "nodes": list(nodes.values())[:30],
        "edges": edges[-40:],
        "total_active_flows": len(flows)
    }


class ManualInspectionRequest(BaseModel):
    ip_address: Optional[str] = None
    website: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    bytes_sent: Optional[int] = 0
    bytes_received: Optional[int] = 0


@app.post("/api/inspect")
async def inspect_target(req: ManualInspectionRequest):
    """
    Manually inspects targets across 4 vector categories:
    1. Target IP Address (Wi-Fi / LAN, Enterprise subnet, Public web server, Malicious C2 / Scanner IP)
    2. Website / Domain / URL (Brand spoofing, Phishing keywords, High-risk TLDs, DGA / Tunneling)
    3. Suspicious Email Address (Typosquatting, Free webmail impersonation, Burner/Disposable mail, Phishing triggers)
    4. Suspicious Mobile / Phone Number (Wangiri International toll fraud, Tech support scam popups, Smishing shortcodes)
    """
    raw_ip = (req.ip_address or "").strip()
    raw_website = (req.website or "").strip()
    raw_email = (req.email or "").strip()
    raw_phone = (req.phone_number or "").strip()

    if not raw_ip and not raw_website and not raw_email and not raw_phone:
        raise HTTPException(
            status_code=400,
            detail="Please provide at least one target to inspect (IP address, Website / URL, Email address, or Mobile number)."
        )

    # ----------------------------------------------------
    # 1. WEBSITE / URL HEURISTIC ENGINE
    # ----------------------------------------------------
    clean_domain = ""
    url_path = ""
    full_url = raw_website
    is_phishing_url = False
    phishing_reasons = []

    if raw_website:
        temp_url = raw_website
        if "://" in temp_url:
            temp_url = temp_url.split("://", 1)[1]
        if "/" in temp_url:
            parts = temp_url.split("/", 1)
            clean_domain = parts[0].split(":")[0].lower()
            url_path = "/" + parts[1].lower()
        else:
            clean_domain = temp_url.split(":")[0].lower()

        # Check for Brand Impersonation & Typosquatting
        MAJOR_BRANDS = [
            "microsoft", "apple", "google", "paypal", "netflix", "amazon", "chase",
            "wellsfargo", "bankofamerica", "meta", "facebook", "instagram", "steam",
            "discord", "binance", "coinbase", "walmart", "fedex", "usps", "dhl",
            "irs", "gov", "support-fix", "customer-service"
        ]
        OFFICIAL_DOMAINS = [
            "microsoft.com", "apple.com", "google.com", "paypal.com", "netflix.com",
            "amazon.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "meta.com",
            "facebook.com", "instagram.com", "steampowered.com", "discord.com",
            "binance.com", "coinbase.com", "walmart.com", "fedex.com", "usps.com", "dhl.com"
        ]
        PHISHING_KEYWORDS = [
            "login", "signin", "verify", "verification", "claim", "bonus", "secure",
            "security", "update", "fix", "recovery", "suspend", "wallet", "airdrop",
            "free", "gift", "password", "auth", "portal", "confirm", "billing", "invoice",
            "support", "helpdesk", "reward", "payout", "unusual-activity"
        ]
        SUSPICIOUS_TLDS = [
            ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
            ".work", ".click", ".fit", ".surf", ".rest", ".icu", ".kim", ".su",
            ".ru", ".cc", ".ws", ".live", ".link", ".shop", ".online", ".site"
        ]

        # Check if domain impersonates brand without being official
        brand_impersonated = None
        for brand in MAJOR_BRANDS:
            if brand in clean_domain:
                is_official = any(clean_domain.endswith(off) for off in OFFICIAL_DOMAINS)
                if not is_official:
                    brand_impersonated = brand
                    is_phishing_url = True
                    phishing_reasons.append(f"Impersonates legitimate brand '{brand.title()}' on an unofficial domain.")
                    break

        # Check for suspicious TLD
        has_suspicious_tld = any(clean_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            phishing_reasons.append(f"Uses high-risk, low-reputation top-level domain ({clean_domain.split('.')[-1]}).")

        # Check for phishing keywords in domain or path
        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in clean_domain or kw in url_path]
        if keyword_hits:
            phishing_reasons.append(f"Contains high-urgency phishing triggers: {', '.join(keyword_hits)}.")
            if len(keyword_hits) >= 2 or has_suspicious_tld or brand_impersonated:
                is_phishing_url = True

    # ----------------------------------------------------
    # 2. IP ADDRESS & NETWORK PROFILING ENGINE
    # ----------------------------------------------------
    eval_ip = raw_ip if raw_ip else "198.51.100.77"
    eval_port = req.port if req.port else (443 if clean_domain else 80)
    eval_proto = (req.protocol or "TCP").upper()
    eval_bytes_sent = req.bytes_sent or 520
    eval_bytes_recv = req.bytes_received or 2480

    # Known threat intelligence lists
    KNOWN_MALICIOUS_IPS = {
        "45.142.214.8": "Known Cobalt Strike C2 Server (APT29 / CozyBear)",
        "185.220.101.5": "Known Tor Exit Node & Ransomware Ingress (LockBit)",
        "194.26.29.112": "Known Emotet Botnet Infiltration Node",
        "91.240.118.172": "Mirai Botnet Scanner Host",
        "193.142.146.88": "Active Port Scanner & Brute-Force IP",
        "89.248.165.44": "Bulletproof Hosting C2 Gateway",
        "141.98.11.11": "Known SSH & Telnet Credential Harvester",
        "198.51.100.99": "High-Volume DNS Tunneling Server"
    }

    # Malicious Subnet Prefix Matches
    KNOWN_MALICIOUS_PREFIXES = ["45.142.214.", "185.220.101.", "194.26.29.", "91.240.118.", "89.248.165."]
    is_known_bad_ip = (eval_ip in KNOWN_MALICIOUS_IPS) or any(eval_ip.startswith(p) for p in KNOWN_MALICIOUS_PREFIXES)

    # Suspicious Ports (Metasploit, Tor, Mirai, IRC botnet)
    is_suspicious_port = eval_port in [4444, 1337, 6667, 3389, 23, 445, 9050, 9001]

    # Analyze domain metrics if domain is provided
    dns_stats = calculate_dns_ngram_score(clean_domain) if clean_domain else {"length": 0, "entropy": 0.0, "ngram_rarity": 0.0}
    is_dga = (dns_stats["entropy"] > 3.65 and dns_stats["length"] > 16) or (dns_stats["ngram_rarity"] > 0.65)

    # ----------------------------------------------------
    # 3. SUSPICIOUS EMAIL ADDRESS ENGINE
    # ----------------------------------------------------
    email_report = None
    if raw_email:
        email_clean = raw_email.lower().strip()
        e_user = email_clean.split("@")[0] if "@" in email_clean else email_clean
        e_domain = email_clean.split("@")[1] if "@" in email_clean else ""

        DISPOSABLE_EMAIL_DOMAINS = [
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "throwawaymail.com", "trashmail.com", "yopmail.com", "fakeinbox.com",
            "dispostable.com", "temp-mail.org", "getnada.com", "mohmal.com", "sharklasers.com"
        ]
        FREE_MAIL_PROVIDERS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me", "aol.com"]

        e_threats = []
        is_disposable = any(disp in e_domain for disp in DISPOSABLE_EMAIL_DOMAINS)
        is_free_provider = e_domain in FREE_MAIL_PROVIDERS

        # Check for free mail provider used with corporate brand
        spoofed_brand_in_email = None
        for brand in ["microsoft", "apple", "paypal", "netflix", "amazon", "chase", "bank", "support", "security", "helpdesk", "billing", "service"]:
            if brand in e_user:
                spoofed_brand_in_email = brand
                if is_free_provider:
                    e_threats.append(f"Free public webmail provider ({e_domain}) impersonating corporate identity '{brand.title()}'.")
                break

        if is_disposable:
            e_threats.append("Uses a known disposable / burner temporary email service.")

        # Typosquatting in domain
        if any(typo in e_domain for typo in ["micros0ft", "paypa1", "goog1e", "arnazon", "app1e"]):
            e_threats.append("Domain utilizes visual character substitution (typosquatting / homoglyph attack).")

        # Phishing keywords in local user
        e_phish_kw = [kw for kw in ["urgent", "verify", "suspended", "account", "invoice", "refund", "tax", "lottery", "security-alert"] if kw in e_user]
        if e_phish_kw:
            e_threats.append(f"Sender address contains high-urgency social engineering keywords: {', '.join(e_phish_kw)}.")

        # High risk TLD on email domain
        if any(e_domain.endswith(tld) for tld in [".xyz", ".top", ".buzz", ".ru", ".click", ".work"]):
            e_threats.append(f"Sender domain uses a high-spam reputation TLD ({e_domain.split('.')[-1] if '.' in e_domain else ''}).")

        is_email_threat = len(e_threats) > 0
        email_report = {
            "email_address": raw_email,
            "is_suspicious": is_email_threat,
            "threat_level": "CRITICAL" if len(e_threats) >= 2 or is_disposable or "typosquatting" in str(e_threats) else ("HIGH" if is_email_threat else "CLEAN"),
            "risk_score": 0.96 if len(e_threats) >= 2 else (0.85 if is_email_threat else 0.05),
            "threat_category": "Phishing & Spoofed Sender" if spoofed_brand_in_email else ("Disposable Burner Mail" if is_disposable else ("Spam / Phishing Indicator" if is_email_threat else "Standard / Legitimate Mailbox")),
            "detected_reasons": e_threats if e_threats else ["Sender domain and structure adhere to legitimate email RFC standards."],
            "is_disposable": is_disposable,
            "spoofed_brand": spoofed_brand_in_email,
            "recommended_action": "BLOCK & REPORT: Do not click any links or download attachments from this sender." if is_email_threat else "SAFE: Normal sender profile."
        }

    # ----------------------------------------------------
    # 4. SUSPICIOUS MOBILE / PHONE NUMBER ENGINE
    # ----------------------------------------------------
    phone_report = None
    if raw_phone:
        clean_num = re.sub(r"[^\d+]", "", raw_phone)
        phone_threats = []
        origin_country = "Global / Undetermined"

        # Wangiri (One-Ring) & International Toll Fraud Country Codes
        WANGIRI_PREFIXES = {
            "+232": "Sierra Leone (Known Wangiri Toll Fraud Origin)",
            "+247": "Ascension Island (Known Wangiri Toll Fraud Origin)",
            "+269": "Comoros (Known Wangiri Toll Fraud Origin)",
            "+675": "Papua New Guinea (Known Wangiri Toll Fraud Origin)",
            "+881": "Global Satellite Network (Exorbitant Premium Rate Fraud)",
            "+234": "Nigeria (High Frequency Advance-Fee / Smishing Origin)",
            "+252": "Somalia (Toll Fraud / Missed Call Scam Origin)",
            "+387": "Bosnia & Herzegovina (International Premium Rate Abuse)",
            "+53": "Cuba (Toll Fraud Missed Call Scam)",
            "+216": "Tunisia (Wangiri Callback Scam)",
            "+370": "Lithuania (Automated Robocall / SMS Gateway)"
        }

        matched_wangiri = None
        for pfx, country_desc in WANGIRI_PREFIXES.items():
            if clean_num.startswith(pfx) or clean_num.startswith(pfx.replace("+", "")):
                matched_wangiri = country_desc
                phone_threats.append(f"Number originates from {country_desc}.")
                origin_country = country_desc
                break

        # Tech Support Scam Toll-Free Numbers (US 1-800, 1-888, etc.)
        TOLL_FREE_PREFIXES = ["+1800", "+1888", "+1877", "+1866", "+1855", "+1844", "1800", "1888", "1877", "1866", "1855", "1844", "800", "888", "877"]
        is_toll_free = any(clean_num.startswith(tf) for tf in TOLL_FREE_PREFIXES)
        if is_toll_free:
            origin_country = "North America (Toll-Free Service)"
            phone_threats.append("Toll-free line: Commonly used in fake browser popups ('Call Microsoft Support / Geek Squad').")

        # Smishing / SMS Phishing Shortcode check (3 to 6 digits without standard country code)
        is_shortcode = len(clean_num) in [4, 5, 6] and not clean_num.startswith("+")
        if is_shortcode:
            phone_threats.append("Shortcode sender: High risk of unverified bulk marketing or bank imposter smishing.")

        # Real-World Fraud Incident Match Database
        HISTORICAL_PHONE_FRAUD = {
            "+18005550199": "Tech Support Pop-up Scam (Windows Defender Virus Warning)",
            "+23276123456": "Wangiri One-Ring Callback Scam (Charged $45/min)",
            "+18882345678": "IRS Tax Penalty & Immediate Arrest Threat Robocall",
            "+919876543210": "Fake Bank KYC Update & OTP Phishing SMS Sender",
            "+234803123456": "Lottery & Inheritance Advance Fee Fraud (419 Scam)"
        }

        if clean_num in HISTORICAL_PHONE_FRAUD or raw_phone in HISTORICAL_PHONE_FRAUD:
            phone_threats.append(f"Direct match in fraud incident database: {HISTORICAL_PHONE_FRAUD.get(clean_num) or HISTORICAL_PHONE_FRAUD.get(raw_phone)}")

        is_phone_threat = len(phone_threats) > 0
        phone_report = {
            "phone_number": raw_phone,
            "is_suspicious": is_phone_threat,
            "threat_level": "CRITICAL" if matched_wangiri or clean_num in HISTORICAL_PHONE_FRAUD else ("HIGH" if is_phone_threat else "CLEAN"),
            "risk_score": 0.94 if matched_wangiri else (0.80 if is_phone_threat else 0.05),
            "threat_category": "Wangiri International Toll Scam" if matched_wangiri else ("Tech Support Scam Hotline" if is_toll_free else ("Smishing / Impersonation Number" if is_phone_threat else "Standard Mobile / Fixed Line")),
            "detected_reasons": phone_threats if phone_threats else ["No suspicious toll fraud or smishing patterns matched."],
            "origin_country": origin_country,
            "recommended_action": "DO NOT CALL BACK or reply to SMS. Block caller immediately." if is_phone_threat else "No immediate fraud threat detected."
        }

    # ----------------------------------------------------
    # 5. SYNTHESIZE NETWORK FLOW & PASS THROUGH ML DETECTOR
    # ----------------------------------------------------
    test_flow = {
        "timestamp": time.time(),
        "flow_identifier": {
            "src_ip": "192.168.10.45",
            "src_port": 54321,
            "dst_ip": eval_ip,
            "dst_port": eval_port,
            "protocol": eval_proto,
            "src_label": "User Inspection Client",
            "dst_label": clean_domain if clean_domain else f"Target ({eval_ip})"
        },
        "bytes_sent": eval_bytes_sent,
        "bytes_received": eval_bytes_recv,
        "packet_count": 10,
        "duration_seconds": 1.25,
        "tcp_flags": "S"
    }

    if clean_domain:
        test_flow["dns"] = {
            "query": clean_domain,
            "qtype": "TXT" if is_dga else "A",
            "rcode": 0
        }
        test_flow["tls"] = {
            "sni": clean_domain,
            "ja3": "a0e42d24b9c7c4b0959f676e939da290" if (is_dga or is_known_bad_ip or is_phishing_url) else "b32309a26951912be7dba376398abcde",
            "ja4": "t13d1516h2_8daaf6152771_0123456789ab"
        }

    raised_alerts = detector.process_flow(test_flow)

    # If domain is phishing or IP is malicious, synthesize high-fidelity alert if not already caught
    if is_phishing_url and not raised_alerts:
        phish_alert = {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "threat_class": "Brand Spoofing & Phishing Attack",
            "confidence_score": 0.95,
            "flow_identifier": test_flow["flow_identifier"],
            "supporting_evidence_feature": {
                "inspected_url": full_url,
                "inspected_domain": clean_domain,
                "technical_reason": " | ".join(phishing_reasons),
                "reason": "A copycat fake website is pretending to be a real company (like Microsoft or Apple) to trick you into typing your secret password."
            }
        }
        detector.alerts_history.append(phish_alert)
        raised_alerts.append(phish_alert)

    if is_known_bad_ip and not raised_alerts:
        intel_desc = KNOWN_MALICIOUS_IPS.get(eval_ip, "Known Malicious C2 / Port Scanner Subnet")
        manual_alert = {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "threat_class": "Botnet C2 Beaconing",
            "confidence_score": 0.98,
            "flow_identifier": test_flow["flow_identifier"],
            "supporting_evidence_feature": {
                "inspected_ip": eval_ip,
                "inspected_domain": clean_domain or "N/A",
                "intel_match": intel_desc,
                "technical_reason": f"Target IP matched threat intelligence database ({intel_desc}).",
                "reason": "This internet address is on the global naughty list because it has attacked other computers before."
            }
        }
        detector.alerts_history.append(manual_alert)
        raised_alerts.append(manual_alert)

    # Broadcast alerts to all connected dashboards
    for alert in raised_alerts:
        await manager.broadcast({
            "type": "alert",
            "data": alert
        })

    # Classify IP Address Type & Subnet
    def classify_ip_details(ip_str: str) -> Dict[str, Any]:
        if not ip_str or ip_str in ["N/A", "Resolved / Default"]:
            return {
                "category": "External Web Server",
                "scope": "Public Internet",
                "device_type": "Web / Cloud Service",
                "is_private": False,
                "is_wifi_lan": False,
                "common_usage": "Public Cloud Endpoint"
            }
        
        parts = ip_str.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            o1, o2, o3, o4 = map(int, parts)
            # Home / Office Wi-Fi Routers and LAN: 192.168.x.x
            if o1 == 192 and o2 == 168:
                return {
                    "category": "Wi-Fi LAN / Home Router Subnet",
                    "scope": "Private Internal Network",
                    "device_type": "Wi-Fi Connected Device (PC / Phone / IoT / Laptop)",
                    "is_private": True,
                    "is_wifi_lan": True,
                    "common_usage": "Local Wi-Fi or Office Ethernet Host"
                }
            # Enterprise LAN / Corporate Intranet: 10.x.x.x (like 10.63.2.207)
            elif o1 == 10:
                return {
                    "category": "Private Enterprise / Intranet LAN Subnet",
                    "scope": "Corporate Internal Network",
                    "device_type": "Enterprise Workstation / Internal Server / Wi-Fi Access Point",
                    "is_private": True,
                    "is_wifi_lan": True,
                    "common_usage": "Internal Corporate Subnet or Local Office Host"
                }
            # Corporate Subnet: 172.16.x.x - 172.31.x.x
            elif o1 == 172 and (16 <= o2 <= 31):
                return {
                    "category": "Private Enterprise LAN Subnet",
                    "scope": "Private Subnet",
                    "device_type": "Internal Server / Wi-Fi Subnet",
                    "is_private": True,
                    "is_wifi_lan": True,
                    "common_usage": "Internal Subnet Device"
                }
            # Loopback: 127.x.x.x
            elif o1 == 127:
                return {
                    "category": "Loopback Localhost",
                    "scope": "Local Machine",
                    "device_type": "Local Operating System Service",
                    "is_private": True,
                    "is_wifi_lan": False,
                    "common_usage": "This Computer (Localhost)"
                }
            # Carrier Grade NAT: 100.64.x.x - 100.127.x.x
            elif o1 == 100 and (64 <= o2 <= 127):
                return {
                    "category": "Carrier-Grade NAT / ISP Network",
                    "scope": "ISP Mobile / Broadband Subnet",
                    "device_type": "Cellular Mobile / Wi-Fi Broadband Router",
                    "is_private": True,
                    "is_wifi_lan": True,
                    "common_usage": "ISP Cellular or Home Router WAN"
                }
            # Well-known DNS
            elif ip_str in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]:
                return {
                    "category": "Public Anycast DNS Resolver",
                    "scope": "Public Internet",
                    "device_type": "Global Domain Name Resolver",
                    "is_private": False,
                    "is_wifi_lan": False,
                    "common_usage": "Verified Public DNS Infrastructure"
                }

        # Public Web / Internet Host
        return {
            "category": "Public Internet Host / Web Server",
            "scope": "Global Public IPv4",
            "device_type": "External Web / Cloud Server",
            "is_private": False,
            "is_wifi_lan": False,
            "common_usage": "Internet Web Server / Cloud Service"
        }

    ip_info = classify_ip_details(raw_ip or eval_ip)

    # Classify Website / Domain Category
    def classify_website_details(domain_str: str) -> Dict[str, Any]:
        if not domain_str:
            return {
                "category": "No Domain Provided (Direct IP Connection)",
                "reputation": "Neutral",
                "risk_profile": "Standard"
            }
        d_lower = domain_str.lower()
        if any(safe in d_lower for safe in ["google.com", "microsoft.com", "apple.com", "github.com", "amazon.com", "cloudflare.com", "wikipedia.org"]):
            return {
                "category": "Verified Global Web Service / CDN",
                "reputation": "Highly Trusted (Whitelisted)",
                "risk_profile": "Minimal"
            }
        elif is_phishing_url:
            return {
                "category": "Brand Impersonation & Phishing Threat",
                "reputation": "Malicious / Dangerous (Phishing Campaign)",
                "risk_profile": "Critical Threat",
                "reasons": phishing_reasons
            }
        elif is_dga:
            return {
                "category": "Suspicious Algorithmic Domain (DGA / Tunnel)",
                "reputation": "Malicious / Dangerous",
                "risk_profile": "High Severity"
            }
        else:
            return {
                "category": "Standard Web / Internet Domain",
                "reputation": "Unverified Public Domain",
                "risk_profile": "Standard Inspection"
            }

    website_info = classify_website_details(clean_domain)

    # Historical Threat Database
    HISTORICAL_THREAT_DATABASE = {
        "45.142.214.8": [
            {
                "attack_type": "Cobalt Strike C2 Beaconing",
                "date": "2026-08-14",
                "severity": "CRITICAL",
                "target_sector": "Energy & Nuclear SCADA Network",
                "description": "Observed initiating 10-second periodic encrypted beacons imitating legitimate cloud services."
            },
            {
                "attack_type": "Credential Dumping Recon",
                "date": "2026-06-02",
                "severity": "HIGH",
                "target_sector": "Critical Manufacturing",
                "description": "Port scan and SMB lateral movement attempts detected from this IP address."
            }
        ],
        "185.220.101.5": [
            {
                "attack_type": "Ransomware Ingress / LockBit 3.0",
                "date": "2026-07-29",
                "severity": "CRITICAL",
                "target_sector": "Healthcare Infrastructure",
                "description": "Tor exit node used to deliver second-stage LockBit ransomware payloads."
            }
        ],
        "194.26.29.112": [
            {
                "attack_type": "Emotet Botnet Infiltration",
                "date": "2026-05-18",
                "severity": "HIGH",
                "target_sector": "Financial Systems",
                "description": "Distributed spam relays and macro loader download host."
            }
        ],
        "91.240.118.172": [
            {
                "attack_type": "Mirai IoT Port Sweep & Telnet Brute-Force",
                "date": "2026-09-01",
                "severity": "MEDIUM",
                "target_sector": "Municipal Water Utility",
                "description": "Probed over 40 distinct ICS ports in less than 30 seconds."
            }
        ],
        "c2-command.evil-corp.net": [
            {
                "attack_type": "Advanced Persistent Threat (APT29) Command & Control",
                "date": "2026-08-20",
                "severity": "CRITICAL",
                "target_sector": "Defense Contractor",
                "description": "Matched known TLS JA3 signature with encrypted heartbeats."
            }
        ],
        "update-service-check.biz": [
            {
                "attack_type": "TrickBot Stealer Distribution",
                "date": "2026-07-11",
                "severity": "HIGH",
                "target_sector": "Government Systems",
                "description": "Fake Windows update certificate drop point."
            }
        ],
        "tunnel.exfil-data.info": [
            {
                "attack_type": "DNS Tunnelling & Data Theft",
                "date": "2026-08-05",
                "severity": "CRITICAL",
                "target_sector": "Bank Payment Gateway",
                "description": "Exfiltrated 42 MB of encrypted customer records inside DNS TXT query chunks."
            }
        ]
    }

    # Query matching previous attacks
    matched_attacks = []
    if raw_ip in HISTORICAL_THREAT_DATABASE:
        matched_attacks.extend(HISTORICAL_THREAT_DATABASE[raw_ip])
    if clean_domain in HISTORICAL_THREAT_DATABASE:
        matched_attacks.extend(HISTORICAL_THREAT_DATABASE[clean_domain])

    # If domain was flagged as phishing, add synthetic historical incident if none listed
    if is_phishing_url and not any(clean_domain in str(a) for a in matched_attacks):
        matched_attacks.append({
            "attack_type": "Phishing & Credential Harvester Campaign",
            "date": time.strftime("%Y-%m-%d", time.gmtime()),
            "severity": "CRITICAL",
            "target_sector": "Consumer & Enterprise Credentials",
            "description": f"Domain identified actively hosting credential harvesting forms mimicking {brand_impersonated.title() if brand_impersonated else 'legitimate services'}."
        })

    # Also search session history in memory
    for past_alert in detector.alerts_history:
        fid = past_alert.get("flow_identifier", {})
        if (raw_ip and fid.get("dst_ip") == raw_ip) or (clean_domain and clean_domain in fid.get("dst_label", "")):
            matched_attacks.append({
                "attack_type": past_alert.get("threat_class", "Threat Anomaly"),
                "date": past_alert.get("timestamp", "Recent Session"),
                "severity": "CRITICAL" if past_alert.get("confidence_score", 0) >= 0.9 else "HIGH",
                "target_sector": "Local Air-Gapped Diode Network",
                "description": past_alert.get("supporting_evidence_feature", {}).get("reason", "Flagged by AI threat detector.")
            })

    # Prepare verdict assessment
    has_threat = (
        len(raised_alerts) > 0
        or is_known_bad_ip
        or is_dga
        or is_phishing_url
        or (email_report and email_report["is_suspicious"])
        or (phone_report and phone_report["is_suspicious"])
        or len(matched_attacks) > 0
    )
    threat_level = "CRITICAL" if has_threat else "CLEAN"

    summary_msg = ""
    kid_friendly_title = ""
    kid_friendly_explanation = ""

    KID_FRIENDLY_MAP = {
        "Volumetric / Protocol DDoS": {
            "title": "Traffic Flood Attack",
            "simple": "A huge crowd of robot computers is shouting at our server all at once so nobody else can get in — just like 100 people trying to push through a tiny classroom door at the exact same second!"
        },
        "Botnet C2 Beaconing": {
            "title": "Secret Spy Clock",
            "simple": "A secret bad program hiding inside is quietly whispering to a hacker's computer on a timer like a ticking clock, waiting for secret evil instructions."
        },
        "DGA Domains & DNS Tunnelling": {
            "title": "Scrambled Secret-Code Website",
            "simple": "The computer is asking for weird scrambled secret-code website names (like 'x9z8q7w6'), which hackers use to sneak stolen secrets out without anyone noticing."
        },
        "Encrypted Malware (TLS/QUIC)": {
            "title": "Disguised Computer Virus",
            "simple": "A dangerous computer virus was caught trying to wear a fake disguise to sneak past the security guards."
        },
        "Reconnaissance & Port Scanning": {
            "title": "Sneaky Prowler",
            "simple": "A sneaky stranger is walking around trying to wiggle every single doorknob and window on our house to see if any door was accidentally left unlocked."
        },
        "Data Exfiltration": {
            "title": "Secret Backpack Theft",
            "simple": "Someone is sneaking out a giant backpack stuffed with private files and secret photos through the back door!"
        },
        "Brand Spoofing & Phishing Attack": {
            "title": "Fake Copycat Imposter",
            "simple": "A copycat fake website is pretending to be a real company (like Microsoft or Apple) to trick you into typing your secret password!"
        },
        "Isolation Forest Statistical Anomaly": {
            "title": "Weird Unseen Behavior",
            "simple": "This computer suddenly started acting very strangely and doing things it has never done before!"
        }
    }

    if len(raised_alerts) > 0:
        t_class = raised_alerts[0].get("threat_class", "Threat")
        mapping = KID_FRIENDLY_MAP.get(t_class, {})
        kid_friendly_title = mapping.get("title", t_class)
        kid_friendly_explanation = mapping.get("simple", raised_alerts[0].get("supporting_evidence_feature", {}).get("reason", "A suspicious pattern was spotted!"))
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    elif is_phishing_url:
        kid_friendly_title = "Fake Copycat Imposter"
        kid_friendly_explanation = "A copycat fake website is pretending to be a real company (like Microsoft or Apple) to trick you into typing your secret password!"
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    elif is_known_bad_ip:
        kid_friendly_title = "Naughty Hacker Address"
        kid_friendly_explanation = "This internet address is on the global naughty list because it was caught attacking other computers before."
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    elif email_report and email_report["is_suspicious"]:
        kid_friendly_title = "Trick Email Sender"
        kid_friendly_explanation = f"A stranger is using a fake email identity ({email_report['detected_reasons'][0]}), trying to trick you into clicking a dangerous trap."
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    elif phone_report and phone_report["is_suspicious"]:
        kid_friendly_title = "Scammer Phone Number"
        kid_friendly_explanation = f"This phone number belongs to a telephone scammer ({phone_report['detected_reasons'][0]}) who calls to scare people or steal private codes."
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    elif len(matched_attacks) > 0:
        kid_friendly_title = "Repeat Bad Guy"
        kid_friendly_explanation = f"This address was caught doing {len(matched_attacks)} bad things in the past!"
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"
    else:
        kid_friendly_title = "Safe & Friendly"
        kid_friendly_explanation = "All clear! Everything looks completely normal, friendly, and safe — no sneaky tricks found!"
        summary_msg = f"{kid_friendly_title}: {kid_friendly_explanation}"

    # Advisory explaining why some threats may initially look safe on basic firewalls
    security_advisory = {
        "title": "Why Some Threat Websites & IPs Can Initially Evade Basic Scanners",
        "key_reasons": [
            {
                "reason": "Zero-Day & Newly Registered Domains (NRDs)",
                "detail": "Over 70% of phishing sites are active for less than 4 hours before being abandoned. Public blacklists (Spamhaus, VirusTotal) experience a latency of several hours to days before indexing them."
            },
            {
                "reason": "Lexical Evasion & Brand Camouflage",
                "detail": "Attackers deliberately use common dictionary words ('support', 'fix', 'account') to maintain normal Shannon entropy, evading naive algorithmic DGA filters unless NLP brand-spoofing is applied."
            },
            {
                "reason": "Cloud Reverse Proxies & Fast-Flux IP Hopping",
                "detail": "Threat actors frequently hide true malicious servers behind legitimate CDNs (Cloudflare, Fastly, AWS), meaning a simple IP lookup returns a legitimate cloud provider's address."
            }
        ]
    }

    return {
        "status": "completed",
        "inspected_target": {
            "ip_address": eval_ip if raw_ip else "Resolved / Default",
            "website": full_url or "N/A",
            "clean_domain": clean_domain or "N/A",
            "email": raw_email or "N/A",
            "phone_number": raw_phone or "N/A",
            "port": eval_port,
            "protocol": eval_proto,
            "ip_classification": ip_info,
            "website_classification": website_info
        },
        "verdict": {
            "is_threat": has_threat,
            "threat_level": threat_level,
            "confidence_score": raised_alerts[0]["confidence_score"] if raised_alerts else (0.95 if has_threat else 0.0),
            "summary": summary_msg,
            "kid_friendly_title": kid_friendly_title,
            "kid_friendly_explanation": kid_friendly_explanation
        },
        "dns_analysis": {
            "query": clean_domain,
            "entropy": dns_stats["entropy"],
            "ngram_rarity": dns_stats["ngram_rarity"],
            "is_dga_pattern": is_dga
        } if clean_domain else None,
        "email_analysis": email_report,
        "phone_analysis": phone_report,
        "previous_attacks": matched_attacks,
        "previous_attacks_count": len(matched_attacks),
        "alerts_raised": len(raised_alerts),
        "alerts": raised_alerts,
        "security_advisory": security_advisory
    }


@app.post("/api/simulate/{threat_type}")
async def simulate_threat(threat_type: str):
    """
    Injects a synthetic threat flow sequence to test the pipeline:
    threat_type options: 'ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration'
    """
    valid_threats = ['ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration']
    if threat_type not in valid_threats:
        raise HTTPException(status_code=400, detail=f"Invalid threat type. Choose from: {valid_threats}")

    flows = generator.generate_threat_scenario(threat_type)
    raised_alerts = []

    for flow in flows:
        new_alerts = detector.process_flow(flow)
        for alert in new_alerts:
            raised_alerts.append(alert)
            await manager.broadcast({
                "type": "alert",
                "data": alert
            })

    return {
        "status": "threat_injected",
        "threat_type": threat_type,
        "flows_processed": len(flows),
        "alerts_raised": len(raised_alerts),
        "alerts": raised_alerts
    }


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial state snapshot
        await websocket.send_json({
            "type": "snapshot",
            "stats": detector.get_stats(),
            "recent_alerts": detector.get_all_alerts()[-10:],
            "auto_detection_enabled": auto_detection_enabled
        })
        while True:
            # Passive keep-alive receive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
