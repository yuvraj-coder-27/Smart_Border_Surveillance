"""
src/audit_logger.py
===================
Security & Compliance Audit Logger.

Records operational actions (logins, alert triaging, zone mutations,
blockchain verification, and evidence exports) into an immutable audit trail.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional

from database.db import get_db
from database.models import AuditLog
from utils.logger import logger


def log_audit_event(
    user_callsign: str,
    role: str,
    action: str,
    resource: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: str = "127.0.0.1",
) -> Optional[int]:
    """Record an operational action to the database audit trail."""
    try:
        with get_db() as db:
            log_entry = AuditLog(
                timestamp=datetime.utcnow(),
                user_callsign=user_callsign,
                role=role,
                action=action,
                resource=resource,
                details=details or {},
                ip_address=ip_address,
            )
            db.add(log_entry)
            db.flush()
            log_id = log_entry.id
            logger.info(f"Audit Log #{log_id} recorded: [{role}] {user_callsign} -> {action} on {resource}")
            return log_id
    except Exception as e:
        logger.warning(f"Failed to record audit event: {e}")
        return None


def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    action: Optional[str] = None,
    role: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve audit trail logs with filtering."""
    try:
        with get_db() as db:
            q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
            if action:
                q = q.filter(AuditLog.action == action)
            if role:
                q = q.filter(AuditLog.role == role)
            total = q.count()
            rows = q.offset(offset).limit(limit).all()
            return {"total": total, "logs": [r.to_dict() for r in rows]}
    except Exception as e:
        logger.error(f"Error querying audit logs: {e}")
        return {"total": 0, "logs": []}
