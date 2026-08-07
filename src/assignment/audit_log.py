"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        request_id = request_id or f"req-{len(self.logs)}"
        self._open[request_id] = {
            "user_id": user_id,
            "input": text,
            "timestamp": utc_now_iso(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        latency_ms: float | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        request_id = request_id or f"req-{len(self.logs)}"
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "timestamp": utc_now_iso(),
            "latency_ms": latency_ms,
        }
        if request_id in self._open:
            entry["input"] = self._open[request_id].get("input", "")
            del self._open[request_id]
        self.logs.append(entry)

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, ensure_ascii=False, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
