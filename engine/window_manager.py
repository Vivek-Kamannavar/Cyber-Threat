"""
Streaming Sliding Window Manager
Maintains in-memory ring buffers and sliding time windows for streaming network telemetry.
Bounded memory footprint and zero return-path side effects for Data Diode setups.
Hardened with thread and asyncio locks for concurrent read/write safety.
"""

import time
import threading
import asyncio
from collections import deque, defaultdict
from typing import List, Dict, Any, Optional


class SlidingWindowManager:
    """Manages sliding time window (e.g., 60s) of incoming network flow records with full concurrency protection."""

    def __init__(self, window_size_seconds: float = 60.0):
        self.window_size = window_size_seconds
        self.flows = deque()
        self.src_ip_history = defaultdict(list)  # src_ip -> list of flow dicts
        self.dst_ip_history = defaultdict(list)  # dst_ip -> list of flow dicts
        self._thread_lock = threading.RLock()
        self._async_lock: Optional[asyncio.Lock] = None

    @property
    def async_lock(self) -> asyncio.Lock:
        """Lazily initializes the asyncio.Lock within the active running event loop."""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def add_flow(self, flow: Dict[str, Any]):
        """Appends a new normalized flow and purges records outside the sliding window (thread-safe)."""
        with self._thread_lock:
            now = flow.get('timestamp', time.time())
            self.flows.append(flow)

            src_ip = flow['flow_identifier']['src_ip']
            dst_ip = flow['flow_identifier']['dst_ip']
            self.src_ip_history[src_ip].append(flow)
            self.dst_ip_history[dst_ip].append(flow)

            self._purge_old_flows(now)

    async def async_add_flow(self, flow: Dict[str, Any]):
        """Asynchronously appends a new flow using asyncio.Lock."""
        async with self.async_lock:
            self.add_flow(flow)

    def _purge_old_flows(self, current_time: float):
        """Purges flows older than current_time - window_size (caller must hold lock or uses reentrant lock)."""
        with self._thread_lock:
            cutoff = current_time - self.window_size

            while self.flows and self.flows[0].get('timestamp', 0) < cutoff:
                old_flow = self.flows.popleft()
                src_ip = old_flow['flow_identifier']['src_ip']
                dst_ip = old_flow['flow_identifier']['dst_ip']

                if src_ip in self.src_ip_history:
                    self.src_ip_history[src_ip] = [
                        f for f in self.src_ip_history[src_ip] if f.get('timestamp', 0) >= cutoff
                    ]
                    if not self.src_ip_history[src_ip]:
                        del self.src_ip_history[src_ip]

                if dst_ip in self.dst_ip_history:
                    self.dst_ip_history[dst_ip] = [
                        f for f in self.dst_ip_history[dst_ip] if f.get('timestamp', 0) >= cutoff
                    ]
                    if not self.dst_ip_history[dst_ip]:
                        del self.dst_ip_history[dst_ip]

    def get_recent_flows(self) -> List[Dict[str, Any]]:
        """Returns a defensive shallow copy of all flows currently within the sliding window."""
        with self._thread_lock:
            return list(self.flows)

    async def async_get_recent_flows(self) -> List[Dict[str, Any]]:
        """Asynchronously retrieves recent flows with asyncio.Lock."""
        async with self.async_lock:
            return self.get_recent_flows()

    def get_flows_for_src_ip(self, src_ip: str) -> List[Dict[str, Any]]:
        """Returns a defensive shallow copy of flows from a specific source IP within the sliding window."""
        with self._thread_lock:
            return list(self.src_ip_history.get(src_ip, []))

    def get_throughput_stats(self) -> Dict[str, Any]:
        """Calculates current packet rate (pps) and byte rate (bps) over sliding window using frozen snapshot."""
        with self._thread_lock:
            flows_snapshot = list(self.flows)

        if not flows_snapshot:
            return {"pps": 0.0, "bps": 0.0, "total_flows": 0}

        total_bytes = sum(f.get('bytes_sent', 0) + f.get('bytes_received', 0) for f in flows_snapshot)
        total_packets = sum(f.get('packet_count', 1) for f in flows_snapshot)

        window_duration = max(1.0, self.window_size)
        return {
            "pps": round(total_packets / window_duration, 2),
            "bps": round((total_bytes * 8) / window_duration, 2),
            "total_bytes": total_bytes,
            "total_flows": len(flows_snapshot)
        }
