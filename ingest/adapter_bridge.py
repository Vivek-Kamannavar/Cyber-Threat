"""
Out-of-band internet threat-intelligence ingestion bridge.

Wraps the ``@shrinivas-sn/adapter-ingestion`` package (default ``E:\\adapter-ingestion``)
so the SOC can turn public/no-API sources into local, deduplicated indicator records,
and accept normalized packet events from an external collector onto the diode side.

Compliance note (see RULE.md 1.1 / 1.2):
- The adapter pipeline runs **out of band**, never inside the detection enclave and never
  against the monitored interface. It only writes JSONL into its own store directory.
- The enclave itself performs zero live network lookups: it reads the local JSONL store
  (or the derived cache file) and matches indicators entirely in memory.
- This module opens no outbound sockets and emits no packets; it only shells out to the
  package runner when ``refresh()`` is explicitly called.

Two ingestion paths are supported:

1. **Threat-intel feed** (`AdapterFeedBridge`) — runs adapter pipelines, normalizes each
   stored record into an indicator (``ipv4`` / ``domain`` / ``url`` / ``sha256``) and keeps
   a bounded local cache the API can read.
2. **Collector stream** (`normalize_event` / `ingest_stream_batch`) — accepts batches of
   already-observed packet events from the diode-side collector, normalizes them into the
   engine flow schema and feeds ``ThreatDetector.process_flow``.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("adapter_bridge")

DEFAULT_PACKAGE_DIR = os.getenv("ADAPTER_INGESTION_DIR", r"E:\adapter-ingestion")

# Bounded state (RULE 2.1): cap indicators, accepted events and dedupe memory.
MAX_INDICATORS = 500
MAX_STREAM_EVENTS = 2000
DEDUPE_MAX_KEYS = 5000
DEDUPE_TTL_SECONDS = 30.0

# Where the enclave keeps the derived, air-gapped indicator cache.
DEFAULT_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "data", "threat_intel.json"
)

# Field names that commonly carry an indicator value, checked before the generic scan.
INDICATOR_FIELDS = (
    "ip", "ip_address", "ipv4", "ipv6", "address", "indicator",
    "domain", "hostname", "host", "url", "link",
    "sha256", "sha1", "md5", "hash",
)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+\.?$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)


# ----------------------------------------------------------------------
# Record normalization
# ----------------------------------------------------------------------
def classify_indicator(value: Any) -> Optional[str]:
    """Returns the indicator type for a raw value, or None when it is not an indicator."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().strip('"').strip("'")
    if not candidate or len(candidate) > 512:
        return None

    if _URL_RE.match(candidate):
        return "url"

    match = _IPV4_RE.match(candidate)
    if match and all(0 <= int(part) <= 255 for part in match.groups()):
        return "ipv4"
    if ":" in candidate:
        try:
            ipaddress.IPv6Address(candidate)
            return "ipv6"
        except ValueError:
            pass

    if _HASH_RE.match(candidate):
        return "sha256" if len(candidate) == 64 else "md5"
    if _DOMAIN_RE.match(candidate) and not candidate.replace(".", "").isdigit():
        return "domain"
    return None


def _coerce_severity(value: Any) -> str:
    """Maps arbitrary severity/confidence hints onto the four SOC ratings."""
    if isinstance(value, (int, float)):
        score = float(value)
        if score > 1:  # treat 0-100 scales as percentages
            score = score / 100.0
        if score >= 0.9:
            return "CRITICAL"
        if score >= 0.75:
            return "HIGH"
        if score >= 0.5:
            return "MEDIUM"
        return "LOW"
    if isinstance(value, str):
        upper = value.strip().upper()
        if upper in SEVERITY_ORDER:
            return upper
    return "MEDIUM"


def _iter_candidates(fields: Dict[str, Any], record: Dict[str, Any]) -> Iterable[Any]:
    """Yields possible indicator values, named fields first, then a generic scan."""
    for name in INDICATOR_FIELDS:
        if name in fields:
            yield fields[name]
    for key in ("indicator", "value", "target", "entity"):
        if key in record:
            yield record[key]
    for value in fields.values():
        yield value
    for value in record.values():
        yield value


def normalize_record(record: Dict[str, Any], source_host: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Converts one stored adapter-ingestion record into an indicator, or returns None
    when the record carries no usable indicator value.
    """
    if not isinstance(record, dict):
        return None

    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    host = source_host or record.get("source_host") or "unknown-source"

    indicator = None
    indicator_type = None
    for candidate in _iter_candidates(fields, record):
        if isinstance(candidate, list):
            for item in candidate:
                kind = classify_indicator(item)
                if kind:
                    indicator, indicator_type = str(item).strip(), kind
                    break
        else:
            kind = classify_indicator(candidate)
            if kind:
                indicator, indicator_type = str(candidate).strip(), kind
        if indicator:
            break

    if not indicator or not indicator_type:
        return None

    severity = _coerce_severity(
        fields.get("severity", fields.get("risk", fields.get("confidence", record.get("severity"))))
    )

    title = (
        fields.get("title")
        or fields.get("name")
        or fields.get("description")
        or fields.get("threat")
        or f"{indicator_type} indicator from {host}"
    )

    return {
        "indicator_id": str(record.get("id") or f"{host}:{indicator}"),
        "indicator": indicator,
        "indicator_type": indicator_type,
        "severity": severity,
        "title": str(title)[:300],
        "source_host": host,
        "source_url": record.get("source_url") or fields.get("url") or "",
        "observed_at": record.get("fetched_at") or "",
    }


def load_store_records(store_file: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Reads an append-only adapter store as JSONL, collapsing it to last-write-wins per id.
    Malformed lines are counted and skipped so a corrupted tail never breaks ingestion.
    """
    if not os.path.isfile(store_file):
        return [], 0

    latest: Dict[str, Dict[str, Any]] = {}
    malformed = 0
    try:
        with open(store_file, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    malformed += 1
                    continue
                if not isinstance(record, dict):
                    malformed += 1
                    continue
                key = str(record.get("id") or record.get("source_id") or len(latest))
                latest[key] = record
    except OSError as exc:
        logger.warning("Could not read adapter store %s: %s", store_file, exc)
        return [], malformed

    return list(latest.values()), malformed


def dedupe_indicators(indicators: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates indicators by value, keeping the highest severity observation."""
    best: Dict[str, Dict[str, Any]] = {}
    for indicator in indicators:
        if not isinstance(indicator, dict):
            continue
        key = f"{indicator.get('indicator_type')}:{indicator.get('indicator')}"
        current = best.get(key)
        if current is None:
            best[key] = indicator
            continue
        if SEVERITY_ORDER.get(indicator.get("severity", ""), 0) > SEVERITY_ORDER.get(current.get("severity", ""), 0):
            best[key] = indicator
    return sorted(best.values(), key=lambda item: item.get("indicator", ""))[:MAX_INDICATORS]


# ----------------------------------------------------------------------
# Adapter-ingestion package runner
# ----------------------------------------------------------------------
def discover_adapters(package_dir: str) -> List[Dict[str, str]]:
    """Lists usable ``<host>.adapter.json`` files shipped by the ingestion package."""
    adapters_dir = os.path.join(package_dir, "adapters")
    if not os.path.isdir(adapters_dir):
        return []

    discovered: List[Dict[str, str]] = []
    for filename in sorted(os.listdir(adapters_dir)):
        if not filename.endswith(".adapter.json"):
            continue
        path = os.path.join(adapters_dir, filename)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                adapter = json.load(handle)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Skipping unusable adapter %s: %s", filename, exc)
            continue
        host = adapter.get("host")
        if isinstance(host, str) and host:
            discovered.append({"host": host, "adapter_path": path, "store_file": os.path.join(package_dir, "store", f"{host}.jsonl")})
    return discovered


class AdapterFeedBridge:
    """
    Runs adapter pipelines out of band and keeps a bounded, local indicator cache.

    ``refresh()`` is the only method that touches the network, and it does so indirectly
    by shelling out to the package runner. Everything else is local file + memory work.
    """

    def __init__(
        self,
        package_dir: Optional[str] = None,
        cache_path: Optional[str] = None,
        node_bin: str = "node",
    ):
        self.package_dir = package_dir or DEFAULT_PACKAGE_DIR
        self.cache_path = cache_path or DEFAULT_CACHE_PATH
        self.node_bin = node_bin
        self._indicators: Optional[List[Dict[str, Any]]] = None
        self._last_refresh: Optional[Dict[str, Any]] = None

    # -- package state -------------------------------------------------
    @property
    def runner_path(self) -> str:
        return os.path.join(self.package_dir, "src", "run.mjs")

    def available(self) -> bool:
        return os.path.isfile(self.runner_path)

    def sources(self) -> List[Dict[str, str]]:
        return discover_adapters(self.package_dir) if self.available() else []

    # -- refresh (out-of-band) ----------------------------------------
    def refresh(self, host: Optional[str] = None, timeout: float = 25.0) -> Dict[str, Any]:
        """
        Executes the adapter runner for the requested host (or every discovered adapter),
        then rebuilds the indicator cache from the package store.
        """
        if not self.available():
            return {
                "status": "unavailable",
                "detail": f"adapter-ingestion runner not found at {self.runner_path}",
                "sources": [],
                "indicators": len(self._indicators or []),
            }

        targets = [src for src in self.sources() if host in (None, src["host"])]
        if not targets:
            return {"status": "no_sources", "detail": f"no adapter found for host {host}", "sources": [], "indicators": 0}

        results: List[Dict[str, Any]] = []
        for target in targets:
            results.append(self._run_adapter(target, timeout))

        indicators = self.reload()
        self._last_refresh = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sources": results,
            "indicators": len(indicators),
        }
        status = "refreshed" if any(r.get("outcome") == "ok" for r in results) else "degraded"
        return {**self._last_refresh, "status": status}

    def _run_adapter(self, target: Dict[str, str], timeout: float) -> Dict[str, Any]:
        """Runs one adapter through the node runner, tolerating every failure mode."""
        command = [self.node_bin, os.path.join("src", "run.mjs"), target["adapter_path"]]
        try:
            completed = subprocess.run(
                command,
                cwd=self.package_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return {"host": target["host"], "outcome": "unavailable", "detail": f"{self.node_bin} executable not found"}
        except subprocess.TimeoutExpired:
            return {"host": target["host"], "outcome": "timeout", "detail": f"adapter run exceeded {timeout}s"}
        except OSError as exc:
            return {"host": target["host"], "outcome": "error", "detail": str(exc)}

        payload: Dict[str, Any] = {}
        try:
            payload = json.loads(completed.stdout or "{}")
        except (json.JSONDecodeError, ValueError):
            payload = {}

        canary_status = (payload.get("canary") or {}).get("status")
        if completed.returncode == 0:
            outcome = "ok"
        elif completed.returncode == 1:
            outcome = "stale" if canary_status == "stale" else "operational_error"
        else:
            outcome = "config_error"

        return {
            "host": target["host"],
            "outcome": outcome,
            "exit_code": completed.returncode,
            "canary_status": canary_status,
            "stages": (payload.get("report") or {}).get("stages"),
            "detail": (completed.stderr or "").strip()[:300],
        }

    # -- local cache ---------------------------------------------------
    def reload(self) -> List[Dict[str, Any]]:
        """Rebuilds the indicator list from the package store files (no network)."""
        collected: List[Dict[str, Any]] = []
        for source in self.sources():
            records, malformed = load_store_records(source["store_file"])
            if malformed:
                logger.warning("Skipped %d malformed line(s) in %s", malformed, source["store_file"])
            for record in records:
                normalized = normalize_record(record, source_host=source["host"])
                if normalized:
                    collected.append(normalized)

        self._indicators = dedupe_indicators(collected)
        self._save_cache()
        return self._indicators

    def indicators(self) -> List[Dict[str, Any]]:
        if self._indicators is None:
            self._indicators = self._load_cache()
        return self._indicators

    def _load_cache(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.cache_path):
            return []
        try:
            with open(self.cache_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Could not read indicator cache %s: %s", self.cache_path, exc)
            return []
        indicators = payload.get("indicators") if isinstance(payload, dict) else None
        return dedupe_indicators(indicators) if isinstance(indicators, list) else []

    def _save_cache(self) -> None:
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "package_dir": self.package_dir,
            "indicators": self._indicators or [],
        }
        try:
            with open(self.cache_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            logger.warning("Could not persist indicator cache %s: %s", self.cache_path, exc)

    # -- status / matching --------------------------------------------
    def status(self) -> Dict[str, Any]:
        indicators = self.indicators()
        by_severity: Dict[str, int] = {}
        for indicator in indicators:
            key = indicator.get("severity", "MEDIUM")
            by_severity[key] = by_severity.get(key, 0) + 1

        sources = []
        for source in self.sources():
            last_run = self._last_refresh_source(source["host"]) if self._last_refresh else None
            sources.append(
                {
                    "host": source["host"],
                    "store_file": source["store_file"],
                    "records": len(load_store_records(source["store_file"])[0]),
                    "label": source["host"],
                    "last_run": last_run,
                }
            )

        return {
            "available": self.available(),
            "package_dir": self.package_dir,
            "cache_path": self.cache_path,
            "compliance": "Out-of-band collector only: enclave reads local indicators, zero live lookups.",
            "indicator_count": len(indicators),
            "by_severity": by_severity,
            "indicators": indicators[:25],
            "sources": sources,
            "last_refresh": self._last_refresh,
        }

    def _last_refresh_source(self, host: str) -> Optional[Dict[str, Any]]:
        if not self._last_refresh:
            return None
        for result in self._last_refresh.get("sources", []):
            if result.get("host") == host:
                return result
        return None

    def _index(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        index: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for indicator in self.indicators():
            kind = indicator.get("indicator_type")
            value = indicator.get("indicator")
            if kind and value:
                index.setdefault(kind, {})[str(value).lower()] = indicator
        return index

    def match_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Returns cached indicators referenced by a flow's destination IP or DNS query."""
        index = self._index()
        if not index:
            return []

        flow_identifier = flow.get("flow_identifier") or {}
        matches: List[Dict[str, Any]] = []

        dst_ip = str(flow_identifier.get("dst_ip") or "").lower()
        if dst_ip in index.get("ipv4", {}) or dst_ip in index.get("ipv6", {}):
            matches.append(index.get("ipv4", {}).get(dst_ip) or index.get("ipv6", {}).get(dst_ip))

        query = (flow.get("dns") or {}).get("query")
        if isinstance(query, str) and query:
            normalized = query.rstrip(".").lower()
            if normalized in index.get("domain", {}):
                matches.append(index["domain"][normalized])

        return [match for match in matches if match]


# ----------------------------------------------------------------------
# Collector stream normalization
# ----------------------------------------------------------------------
def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(0, number)


def normalize_event(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Converts one collector packet event into the engine flow schema.

    Accepted input: ``{timestamp, src_ip, dst_ip, bytes, entropy, flags}`` with
    optional ``src_port``/``dst_port``/``protocol``/``packet_count``/``dns_query``.
    Returns None for structurally unusable events instead of raising.
    """
    if not isinstance(raw, dict):
        return None

    src_ip = raw.get("src_ip") or raw.get("source_ip")
    dst_ip = raw.get("dst_ip") or raw.get("destination_ip")
    if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
        return None
    try:
        ipaddress.ip_address(src_ip)
        ipaddress.ip_address(dst_ip)
    except ValueError:
        return None

    try:
        timestamp = float(raw.get("timestamp") or raw.get("ts") or time.time())
    except (TypeError, ValueError):
        timestamp = time.time()

    protocol = str(raw.get("protocol") or "TCP").upper()
    if protocol not in ("TCP", "UDP", "ICMP"):
        protocol = "TCP"

    bytes_total = _coerce_int(raw.get("bytes", raw.get("bytes_sent")), 0)
    packet_count = _coerce_int(raw.get("packet_count"), 1) or 1
    flags = str(raw.get("flags") or raw.get("tcp_flags") or "SF")[:8]

    dns_query = raw.get("dns_query") or raw.get("sni") or raw.get("domain")
    dns = {"query": str(dns_query), "qtype": "A"} if isinstance(dns_query, str) and dns_query else None

    flow: Dict[str, Any] = {
        "timestamp": timestamp,
        "flow_identifier": {
            "src_ip": src_ip,
            "src_port": _coerce_int(raw.get("src_port"), 0),
            "dst_ip": dst_ip,
            "dst_port": _coerce_int(raw.get("dst_port"), 0),
            "protocol": protocol,
        },
        "bytes_sent": bytes_total,
        "bytes_received": _coerce_int(raw.get("bytes_received"), 0),
        "packet_count": packet_count,
        "tcp_flags": flags,
        "dns": dns,
        "tls": None,
        "ingest_source": "collector_stream",
    }

    entropy = raw.get("entropy")
    if isinstance(entropy, (int, float)):
        flow["payload_entropy"] = float(entropy)

    return flow


class DedupeWindow:
    """Bounded, TTL-based duplicate suppression so retried collector batches are idempotent."""

    def __init__(self, max_keys: int = DEDUPE_MAX_KEYS, ttl_seconds: float = DEDUPE_TTL_SECONDS):
        self.max_keys = max_keys
        self.ttl_seconds = ttl_seconds
        self._seen: Dict[str, float] = {}

    def _key(self, raw: Dict[str, Any]) -> str:
        return "|".join(
            str(raw.get(field))
            for field in ("timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "bytes", "packet_count")
        )

    def is_duplicate(self, raw: Dict[str, Any], now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        self._prune(now)
        key = self._key(raw)
        if key in self._seen:
            return True
        self._seen[key] = now
        if len(self._seen) > self.max_keys:
            oldest = sorted(self._seen.items(), key=lambda item: item[1])[: len(self._seen) - self.max_keys]
            for stale_key, _ in oldest:
                self._seen.pop(stale_key, None)
        return False

    def _prune(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        stale = [key for key, seen_at in self._seen.items() if seen_at < cutoff]
        for key in stale:
            self._seen.pop(key, None)


def ingest_stream_batch(
    detector: Any,
    events: List[Dict[str, Any]],
    bridge: Optional[AdapterFeedBridge] = None,
    dedupe: Optional[DedupeWindow] = None,
) -> Dict[str, Any]:
    """
    Normalizes and feeds a collector batch into the detection engine.

    Malformed events are counted and skipped; a bad batch never raises out of here.
    """
    dedupe = dedupe or DedupeWindow()
    summary = {"accepted": 0, "rejected": 0, "duplicates": 0, "alerts_raised": 0, "intel_matches": []}

    for raw in (events or [])[:MAX_STREAM_EVENTS]:
        if not isinstance(raw, dict):
            summary["rejected"] += 1
            continue

        if dedupe.is_duplicate(raw):
            summary["duplicates"] += 1
            continue

        flow = normalize_event(raw)
        if flow is None:
            summary["rejected"] += 1
            continue

        if bridge is not None:
            for match in bridge.match_flow(flow):
                summary["intel_matches"].append(
                    {
                        "indicator": match.get("indicator"),
                        "severity": match.get("severity"),
                        "title": match.get("title"),
                        "src_ip": flow["flow_identifier"]["src_ip"],
                        "dst_ip": flow["flow_identifier"]["dst_ip"],
                    }
                )

        try:
            alerts = detector.process_flow(flow) or []
        except Exception as exc:  # a single bad flow must not kill the collector loop
            logger.warning("Flow rejected by detection engine: %s", exc)
            summary["rejected"] += 1
            continue

        summary["accepted"] += 1
        summary["alerts_raised"] += len(alerts)

    return summary
