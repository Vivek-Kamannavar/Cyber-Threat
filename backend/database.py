"""
Persistent SQLite Database Layer
Stores alerts and flow records using SQLite in Write-Ahead Logging (WAL) mode for high concurrency.
Provides synchronous and asynchronous thread-safe helper functions.
"""

import os
import sqlite3
import json
import asyncio
import threading
from typing import List, Dict, Any, Optional
from backend.config import Config

_db_lock = threading.RLock()


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates and returns a connection to SQLite configured with WAL mode."""
    target_path = db_path or Config.DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def init_db(db_path: Optional[str] = None):
    """Initializes database schema if tables do not exist."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            with conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_class TEXT,
                    confidence_score REAL,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    supporting_evidence TEXT,
                    status TEXT DEFAULT 'OPEN',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """)
                conn.execute("""
                CREATE TABLE IF NOT EXISTS flow_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    bytes_sent INTEGER,
                    bytes_recv INTEGER
                );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class);")
        finally:
            conn.close()


def _row_to_alert_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Helper to convert a database row back into the standardized alert schema."""
    evidence_raw = row["supporting_evidence"]
    try:
        evidence = json.loads(evidence_raw) if evidence_raw else {}
    except Exception:
        evidence = {"raw": evidence_raw}

    return {
        "alert_id": row["alert_id"],
        "timestamp": row["timestamp"],
        "threat_class": row["threat_class"],
        "confidence_score": float(row["confidence_score"]) if row["confidence_score"] is not None else 0.0,
        "flow_identifier": {
            "src_ip": row["src_ip"] or "",
            "src_port": int(row["src_port"]) if row["src_port"] is not None else 0,
            "dst_ip": row["dst_ip"] or "",
            "dst_port": int(row["dst_port"]) if row["dst_port"] is not None else 0,
            "protocol": row["protocol"] or "TCP"
        },
        "supporting_evidence_feature": evidence,
        "supporting_evidence": evidence,
        "status": row["status"] or "OPEN",
        "created_at": row["created_at"]
    }


def save_alert(alert_dict: Dict[str, Any], db_path: Optional[str] = None) -> bool:
    """Saves or updates an alert record in SQLite (thread-safe)."""
    init_db(db_path)
    flow_id = alert_dict.get("flow_identifier", {})
    alert_id = alert_dict.get("alert_id")
    timestamp = alert_dict.get("timestamp", "")
    threat_class = alert_dict.get("threat_class", "Unknown Threat")
    confidence_score = float(alert_dict.get("confidence_score", 0.0))

    src_ip = flow_id.get("src_ip", alert_dict.get("src_ip", ""))
    src_port = int(flow_id.get("src_port", alert_dict.get("src_port", 0)))
    dst_ip = flow_id.get("dst_ip", alert_dict.get("dst_ip", ""))
    dst_port = int(flow_id.get("dst_port", alert_dict.get("dst_port", 0)))
    protocol = flow_id.get("protocol", alert_dict.get("protocol", "TCP"))

    evidence = alert_dict.get("supporting_evidence_feature", alert_dict.get("supporting_evidence", {}))
    if not isinstance(evidence, str):
        evidence_json = json.dumps(evidence)
    else:
        evidence_json = evidence

    status = alert_dict.get("status", "OPEN")

    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            with conn:
                conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, threat_class, confidence_score,
                    src_ip, src_port, dst_ip, dst_port, protocol,
                    supporting_evidence, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id, timestamp, threat_class, confidence_score,
                    src_ip, src_port, dst_ip, dst_port, protocol,
                    evidence_json, status
                ))
            return True
        finally:
            conn.close()


def get_all_alerts(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent alerts from SQLite ordered by creation time."""
    init_db(db_path)
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC, timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [_row_to_alert_dict(row) for row in rows]
        finally:
            conn.close()


def get_alert_by_id(alert_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetches a single alert by its unique alert_id."""
    init_db(db_path)
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            if row:
                return _row_to_alert_dict(row)
            return None
        finally:
            conn.close()


def clear_alerts(db_path: Optional[str] = None):
    """Deletes all alert records from the database."""
    init_db(db_path)
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            with conn:
                conn.execute("DELETE FROM alerts;")
        finally:
            conn.close()


def save_flow_record(flow_dict: Dict[str, Any], db_path: Optional[str] = None):
    """Saves a lightweight flow record to SQLite."""
    init_db(db_path)
    fid = flow_dict.get("flow_identifier", {})
    ts = float(flow_dict.get("timestamp", 0.0))
    src_ip = fid.get("src_ip", "")
    dst_ip = fid.get("dst_ip", "")
    bytes_sent = int(flow_dict.get("bytes_sent", 0))
    bytes_recv = int(flow_dict.get("bytes_received", 0))

    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            with conn:
                conn.execute("""
                INSERT INTO flow_records (timestamp, src_ip, dst_ip, bytes_sent, bytes_recv)
                VALUES (?, ?, ?, ?, ?)
                """, (ts, src_ip, dst_ip, bytes_sent, bytes_recv))
        finally:
            conn.close()


# Asynchronous wrappers for non-blocking FastAPI execution
async def async_save_alert(alert_dict: Dict[str, Any], db_path: Optional[str] = None) -> bool:
    return await asyncio.to_thread(save_alert, alert_dict, db_path)


async def async_get_all_alerts(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(get_all_alerts, limit, db_path)


async def async_get_alert_by_id(alert_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(get_alert_by_id, alert_id, db_path)


async def async_clear_alerts(db_path: Optional[str] = None):
    return await asyncio.to_thread(clear_alerts, db_path)
