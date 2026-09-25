"""
blockchain/hasher.py
====================
SHA-256 hashing utilities for tamper-evident evidence recording.
All hashes are deterministic and canonical — same input always → same hash.
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Any


def _canonical(data: Any) -> str:
    """Convert any value to a canonical, sorted JSON string for stable hashing."""
    if isinstance(data, dict):
        return json.dumps(data, sort_keys=True, default=str, ensure_ascii=True)
    return str(data)


def hash_dict(d: dict) -> str:
    """SHA-256 hash of a dictionary (canonical JSON, sorted keys)."""
    return hashlib.sha256(_canonical(d).encode()).hexdigest()


def _normalize_timestamp(ts: Any) -> str:
    if ts is None:
        return ""
    if hasattr(ts, "isoformat"):
        return ts.isoformat()
    return str(ts)


def hash_alert(alert_dict: dict) -> str:
    """
    Canonical hash of an alert record.
    Fields: id, camera_id, alert_type, message, timestamp, risk_score_value.
    Excludes mutable fields like status/operator_feedback.
    """
    raw_risk = alert_dict.get("risk_score")
    if raw_risk is None:
        raw_risk = alert_dict.get("risk_score_value")
    try:
        norm_risk = round(float(raw_risk), 2) if raw_risk is not None else 0.0
    except (ValueError, TypeError):
        norm_risk = 0.0

    raw_factors = alert_dict.get("contributing_factors") or []
    if isinstance(raw_factors, str):
        try:
            raw_factors = json.loads(raw_factors)
        except Exception:
            raw_factors = [raw_factors]

    canonical = {
        "id":              alert_dict.get("id"),
        "camera_id":       str(alert_dict.get("camera_id") or ""),
        "alert_type":      str(alert_dict.get("alert_type") or ""),
        "message":         str(alert_dict.get("message") or ""),
        "timestamp":       _normalize_timestamp(alert_dict.get("timestamp")),
        "risk_score":      norm_risk,
        "contributing":    sorted([str(f) for f in raw_factors]),
    }
    return hashlib.sha256(_canonical(canonical).encode()).hexdigest()


def hash_event(event_dict: dict) -> str:
    """SHA-256 hash of an event record."""
    canonical = {
        "id":         event_dict.get("id"),
        "camera_id":  str(event_dict.get("camera_id") or ""),
        "event_type": str(event_dict.get("event_type") or ""),
        "track_id":   event_dict.get("track_id"),
        "timestamp":  _normalize_timestamp(event_dict.get("timestamp")),
        "zone_id":    event_dict.get("zone_id"),
    }
    return hashlib.sha256(_canonical(canonical).encode()).hexdigest()



def hash_file(file_path: str) -> str:
    """SHA-256 hash of a file's binary content. Returns empty string if file missing."""
    if not file_path or not os.path.exists(file_path):
        return ""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_audit_action(action: str, entity_id: Any, details: dict, timestamp: datetime) -> str:
    """SHA-256 hash of an audit log entry."""
    canonical = {
        "action":    action,
        "entity_id": str(entity_id),
        "details":   details,
        "timestamp": str(timestamp),
    }
    return hashlib.sha256(_canonical(canonical).encode()).hexdigest()
