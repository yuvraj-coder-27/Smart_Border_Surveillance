"""
database/models.py
==================
SQLAlchemy ORM models for the Border Surveillance System.

Tables
------
Detection  – individual YOLO detection records
Track      – persistent multi-frame tracks
Zone       – user-defined geo-fenced polygons
Event      – high-level security events (intrusion, loitering, …)
BaselineStat – per-camera per-hour baseline statistics
RiskScore  – aggregated risk assessment
Alert      – operator-facing alert records
Evidence   – snapshot / clip evidence attached to events/alerts
"""

from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    JSON,
    ForeignKey,
    Text,
    Boolean,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class Detection(Base):
    """One object detection result produced by YOLO for a single frame."""

    __tablename__ = "detection"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    track_id = Column(Integer, nullable=True, index=True)          # linked Track.track_id
    class_name = Column(String(64), nullable=False)
    confidence = Column(Float, nullable=False)
    bbox_x1 = Column(Float, nullable=False)
    bbox_y1 = Column(Float, nullable=False)
    bbox_x2 = Column(Float, nullable=False)
    bbox_y2 = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    visibility_condition = Column(
        String(16), default="daylight", nullable=False
    )  # daylight | low_light | fog

    def __repr__(self) -> str:
        return (
            f"<Detection id={self.id} camera={self.camera_id!r} "
            f"class={self.class_name!r} conf={self.confidence:.2f} "
            f"vis={self.visibility_condition!r} ts={self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# Track
# ---------------------------------------------------------------------------

class Track(Base):
    """Persistent multi-frame track produced by the ByteTracker."""

    __tablename__ = "track"

    id = Column(Integer, primary_key=True, autoincrement=True)
    track_id = Column(Integer, nullable=False, index=True)          # globally unique tracker ID
    camera_id = Column(String(64), nullable=False, index=True)
    object_type = Column(String(64), nullable=False)                # e.g. 'person', 'car'
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_x = Column(Float, nullable=True)
    last_y = Column(Float, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<Track id={self.id} track_id={self.track_id} "
            f"camera={self.camera_id!r} type={self.object_type!r} "
            f"first={self.first_seen} last={self.last_seen}>"
        )


# ---------------------------------------------------------------------------
# Zone
# ---------------------------------------------------------------------------

class Zone(Base):
    """User-defined geo-fenced polygon zone for a camera view."""

    __tablename__ = "zone"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    # Stored as JSON list of [x, y] pairs, e.g. [[10,20],[30,40],[30,20]]
    polygon_points = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    events = relationship("Event", back_populates="zone", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "name": self.name,
            "polygon_points": self.polygon_points or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_active": self.is_active,
        }

    def __repr__(self) -> str:
        n_pts = len(self.polygon_points) if self.polygon_points else 0
        return (
            f"<Zone id={self.id} name={self.name!r} "
            f"camera={self.camera_id!r} points={n_pts} active={self.is_active}>"
        )


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

class Event(Base):
    """High-level security event (intrusion, loitering, abandoned object, …)."""

    __tablename__ = "event"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    event_type = Column(
        String(32), nullable=False, index=True
    )  # intrusion | loitering | abandoned_object | border_crossing
    track_id = Column(Integer, nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    zone_id = Column(Integer, ForeignKey("zone.id"), nullable=True)
    # Arbitrary extra data (coordinates, durations, etc.)
    details = Column(JSON, nullable=True, default=dict)

    # Relationships
    zone = relationship("Zone", back_populates="events")
    evidence = relationship("Evidence", back_populates="event", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "event_type": self.event_type,
            "track_id": self.track_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "zone_id": self.zone_id,
            "details": self.details or {},
        }

    def __repr__(self) -> str:
        return (
            f"<Event id={self.id} type={self.event_type!r} "
            f"camera={self.camera_id!r} track={self.track_id} ts={self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# BaselineStat
# ---------------------------------------------------------------------------

class BaselineStat(Base):
    """
    Per-camera, per-hour, per-day-type baseline activity statistics.
    Used by the risk engine to compute z-score anomaly scores.
    """

    __tablename__ = "baseline_stat"

    __table_args__ = (
        UniqueConstraint("camera_id", "hour_bucket", "day_type", name="uq_baseline_cam_hour_daytype"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    hour_bucket = Column(Integer, nullable=False)       # 0-23
    day_type = Column(String(8), nullable=False)        # weekday | weekend

    # Means
    avg_person_count = Column(Float, default=0.0, nullable=False)
    avg_vehicle_count = Column(Float, default=0.0, nullable=False)
    typical_dwell_time_seconds = Column(Float, default=0.0, nullable=False)
    typical_zone_entries_per_hour = Column(Float, default=0.0, nullable=False)

    # Standard deviations
    stddev_person_count = Column(Float, default=0.0, nullable=False)
    stddev_vehicle_count = Column(Float, default=0.0, nullable=False)
    stddev_dwell_time = Column(Float, default=0.0, nullable=False)
    stddev_zone_entries = Column(Float, default=0.0, nullable=False)

    # Meta
    sample_count = Column(Integer, default=0, nullable=False)
    dismissed_alert_count = Column(Integer, default=0, nullable=False)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "hour_bucket": self.hour_bucket,
            "day_type": self.day_type,
            "avg_person_count": float(self.avg_person_count or 0.0),
            "avg_vehicle_count": float(self.avg_vehicle_count or 0.0),
            "typical_dwell_time_seconds": float(self.typical_dwell_time_seconds or 0.0),
            "typical_zone_entries_per_hour": float(self.typical_zone_entries_per_hour or 0.0),
            "stddev_person_count": float(self.stddev_person_count or 0.0),
            "stddev_vehicle_count": float(self.stddev_vehicle_count or 0.0),
            "stddev_dwell_time": float(self.stddev_dwell_time or 0.0),
            "stddev_zone_entries": float(self.stddev_zone_entries or 0.0),
            "sample_count": int(self.sample_count or 0),
            "dismissed_alert_count": int(self.dismissed_alert_count or 0),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }

    def __repr__(self) -> str:
        return (
            f"<BaselineStat camera={self.camera_id!r} hour={self.hour_bucket} "
            f"day_type={self.day_type!r} samples={self.sample_count}>"
        )


# ---------------------------------------------------------------------------
# RiskScore
# ---------------------------------------------------------------------------

class RiskScore(Base):
    """Aggregated risk score for a camera at a point in time."""

    __tablename__ = "risk_score"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    score = Column(Float, nullable=False)                          # 0.0 – 100.0
    # List of human-readable strings describing what drove the score
    contributing_factors = Column(JSON, nullable=True, default=list)
    # List of Event IDs that contributed to this score
    event_ids = Column(JSON, nullable=True, default=list)
    explainability = Column(JSON, nullable=True, default=dict)

    # Relationships
    alerts = relationship("Alert", back_populates="risk_score", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "score": float(self.score or 0.0),
            "contributing_factors": self.contributing_factors or [],
            "event_ids": self.event_ids or [],
            "explainability": self.explainability or {},
        }

    def __repr__(self) -> str:
        return (
            f"<RiskScore id={self.id} camera={self.camera_id!r} "
            f"score={self.score:.1f} ts={self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(Base):
    """Operator-facing alert derived from a RiskScore."""

    __tablename__ = "alert"

    id = Column(Integer, primary_key=True, autoincrement=True)
    risk_score_id = Column(Integer, ForeignKey("risk_score.id"), nullable=True)
    camera_id = Column(String(64), nullable=False, index=True)
    alert_type = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = Column(String(16), default="open", nullable=False)   # open | dismissed | confirmed
    operator_feedback = Column(Text, nullable=True)
    contributing_factors = Column(JSON, nullable=True, default=list)
    risk_score_value = Column(Float, nullable=True)
    explainability = Column(JSON, nullable=True, default=dict)

    # Relationships
    risk_score = relationship("RiskScore", back_populates="alerts")
    evidence = relationship("Evidence", back_populates="alert", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "alert_type": self.alert_type,
            "type": self.alert_type,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status": self.status,
            "risk_score": self.risk_score_value,
            "risk_score_value": self.risk_score_value,
            "contributing_factors": self.contributing_factors or [],
            "explainability": self.explainability or {},
            "operator_feedback": self.operator_feedback,
        }

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} type={self.alert_type!r} "
            f"camera={self.camera_id!r} status={self.status!r} ts={self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(Base):
    """Snapshot and video-clip evidence linked to an Event and/or Alert."""

    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("event.id"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alert.id"), nullable=True)
    camera_id = Column(String(64), nullable=False, index=True)
    snapshot_path = Column(String(512), nullable=True)
    clip_path = Column(String(512), nullable=True)
    thumbnail_path = Column(String(512), nullable=True)
    # metadata_only = file paths recorded but files not yet uploaded
    # full_synced   = files confirmed present on remote storage
    sync_status = Column(String(16), default="metadata_only", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    event = relationship("Event", back_populates="evidence")
    alert = relationship("Alert", back_populates="evidence")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "alert_id": self.alert_id,
            "camera_id": self.camera_id,
            "snapshot_path": self.snapshot_path,
            "clip_path": self.clip_path,
            "thumbnail_path": self.thumbnail_path,
            "sync_status": self.sync_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Evidence id={self.id} event={self.event_id} alert={self.alert_id} "
            f"camera={self.camera_id!r} sync={self.sync_status!r}>"
        )


# ---------------------------------------------------------------------------
# VehiclePlate (ANPR / ALPR)
# ---------------------------------------------------------------------------

class VehiclePlate(Base):
    """Automatic Number Plate Recognition (ANPR) record linked to a tracked vehicle."""

    __tablename__ = "vehicle_plate"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(String(64), nullable=False, index=True)
    track_id = Column(Integer, nullable=True, index=True)
    plate_number = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, default=0.9, nullable=False)
    vehicle_type = Column(String(32), default="car", nullable=False)
    is_watchlist_match = Column(Boolean, default=False, nullable=False, index=True)
    watchlist_reason = Column(String(256), nullable=True)
    snapshot_path = Column(String(512), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "camera_id": self.camera_id,
            "track_id": self.track_id,
            "plate_number": self.plate_number,
            "confidence": float(self.confidence or 0.0),
            "vehicle_type": self.vehicle_type,
            "is_watchlist_match": self.is_watchlist_match,
            "watchlist_reason": self.watchlist_reason,
            "snapshot_path": self.snapshot_path,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

    def __repr__(self) -> str:
        return (
            f"<VehiclePlate id={self.id} plate={self.plate_number!r} "
            f"type={self.vehicle_type!r} watchlist={self.is_watchlist_match}>"
        )


# ---------------------------------------------------------------------------
# AuditLog (System Security & RBAC)
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """Security and compliance audit log for operator and commander actions."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_callsign = Column(String(64), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    resource = Column(String(128), nullable=False)
    details = Column(JSON, nullable=True, default=dict)
    ip_address = Column(String(64), nullable=True, default="127.0.0.1")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_callsign": self.user_callsign,
            "role": self.role,
            "action": self.action,
            "resource": self.resource,
            "details": self.details or {},
            "ip_address": self.ip_address,
        }

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} user={self.user_callsign!r} "
            f"action={self.action!r} ts={self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# User (Defense Personnel Authentication & RBAC Clearance)
# ---------------------------------------------------------------------------

class User(Base):
    """Database-persisted defense operator profile with cryptographic credentials."""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    salt = Column(String(64), nullable=False)
    callsign = Column(String(128), nullable=False)
    role = Column(String(32), default="OPERATOR", nullable=False, index=True)  # COMMANDER | OPERATOR | ANALYST
    clearance = Column(String(64), default="Level 3 (Operational)", nullable=False)
    station = Column(String(128), default="Northern Frontier C2 HQ", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "callsign": self.callsign,
            "role": self.role,
            "clearance": self.clearance,
            "station": self.station,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"

