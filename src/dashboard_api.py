#!/usr/bin/env python3
"""
src/dashboard_api.py
====================
Border Surveillance System — Unified Innovation Platform API & Video Server.

Features:
  - Live AI Video Capture & MJPEG Stream (/api/video_feed)
  - YOLOv8 Object Detection + ByteTrack + CLAHE Adaptive Perception
  - Intrusion, Loitering, Fence Tampering, Border Crossing Analytics
  - Per-Post Behavioral Baseline Engine & Anomaly Scoring (Innovation 1)
  - Bandwidth-Aware Edge-Cloud Sync Layer (Innovation 2)
  - AI Investigation Assistant Grounded in Surveillance DB (Innovation 3)
  - Blockchain Tamper-Evident Evidence Ledger & Immutable Audit Trail (SIH Theme)
  - SQLite Database (SQLAlchemy) with Full CRUD and Analytics Endpoints
  - Real-Time WebSocket Threat Broadcasting
  - Tactical HUD Frontend Hosting (/ and /static)
"""

import os
import sys
import json
import time
import queue
import asyncio
import threading
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import cv2
import numpy as np
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Project root on sys.path ────────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import settings
from utils.logger import logger

# ── Database Layer ───────────────────────────────────────────────────────────
try:
    from database.db import init_db, get_db
    from database.models import Alert, Event, RiskScore, Evidence, BaselineStat, Zone, Detection, Track, VehiclePlate, AuditLog
    from sqlalchemy import desc, func
    DB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database modules not available: {e}")
    DB_AVAILABLE = False

# ── AI & Analytics Modules ───────────────────────────────────────────────────
try:
    from src.detection import ObjectDetector, BehaviorAnalyzer, FenceTamperingDetector, BorderCrossingDetector
    from src.visualization import Visualizer
    DETECTION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Detection modules not available: {e}")
    DETECTION_AVAILABLE = False

try:
    from analytics.zone_manager import ZoneManager
    from analytics.intrusion import IntrusionDetector
    from analytics.event_fusion import EventFusion
    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False

try:
    from baseline_engine.baseline_model import BaselineModel
    from baseline_engine.anomaly_scoring import AnomalyScorer
    from baseline_engine.feedback_loop import FeedbackLoop
    BASELINE_AVAILABLE = True
    FEEDBACK_AVAILABLE = True
except ImportError:
    BASELINE_AVAILABLE = False
    FEEDBACK_AVAILABLE = False

try:
    from risk_engine.risk_scorer import RiskScorer
    RISK_AVAILABLE = True
except ImportError:
    RISK_AVAILABLE = False

try:
    from sync_layer.metadata_sync import MetadataSync
    from sync_layer.evidence_queue import EvidenceQueue
    _meta_sync = MetadataSync()
    _evidence_queue = EvidenceQueue(_meta_sync)
    _evidence_queue.start_background_sync()
    SYNC_AVAILABLE = True
except ImportError:
    SYNC_AVAILABLE = False
    _meta_sync = None
    _evidence_queue = None

try:
    from assistant.report_generator import InvestigationAssistant
    _assistant = InvestigationAssistant()
    ASSISTANT_AVAILABLE = True
except ImportError:
    ASSISTANT_AVAILABLE = False
    _assistant = None

try:
    from blockchain.evidence_chain import get_evidence_chain
    from blockchain.hasher import hash_alert as _hash_alert
    _evidence_chain = get_evidence_chain()
    BLOCKCHAIN_AVAILABLE = True
    logger.info("Blockchain evidence ledger initialised")
except Exception as e:
    BLOCKCHAIN_AVAILABLE = False
    _evidence_chain = None
    logger.warning(f"Blockchain not available: {e}")

# ── New Feature Modules (ANPR, Evidence Dossier, Auth/RBAC, Audit, Cameras) ───
try:
    from anpr.engine import anpr_engine
    ANPR_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ANPR module not available: {e}")
    ANPR_AVAILABLE = False
    anpr_engine = None

from src.evidence_generator import EvidenceDossierGenerator
_evidence_dossier_gen = EvidenceDossierGenerator(_evidence_chain)

from security.auth import authenticate_user, create_access_token, verify_token, get_current_user, require_role, security_bearer, USERS_DB
from src.audit_logger import log_audit_event, get_audit_logs
from src.camera_manager import camera_manager


# ── Pydantic Request Models ──────────────────────────────────────────────────

class DismissRequest(BaseModel):
    feedback: Optional[str] = None

class ZoneCreate(BaseModel):
    camera_id: str
    name: str
    polygon_points: List[List[float]]

class AssistantQuery(BaseModel):
    question: str

class SourcePayload(BaseModel):
    source: str

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    callsign: str
    role: str = "OPERATOR"
    clearance: str = "Level 3 (Operational)"
    station: str = "Northern Frontier C2 HQ"

class SwitchRoleRequest(BaseModel):
    role: str

class WatchlistAddRequest(BaseModel):
    plate_number: str
    reason: str
    severity: str = "high"
    agency: str = "Tactical C2"

class CameraSwitchPayload(BaseModel):
    camera_id: str


# ── Global WebSocket & State Pools ───────────────────────────────────────────

active_connections: List[WebSocket] = []
_ws_lock = asyncio.Lock()
_event_loop: Optional[asyncio.AbstractEventLoop] = None

_legacy_alerts: List[Dict[str, Any]] = []
_alert_lock = threading.Lock()
MAX_LEGACY = 1000


# ── Surveillance Engine (Live Ingestion & AI Pipeline) ───────────────────────

class ThreadedCamera:
    """High-speed asynchronous hardware capture reader (DirectShow on Windows + 1-frame buffer)."""

    def __init__(self, src, width=640, height=480, target_fps=30):
        self.src = src
        self.width = width
        self.height = height
        self.target_fps = target_fps
        self.cap = None
        self.frame = None
        self.ret = False
        self.running = False
        self.lock = threading.Lock()
        self.thread = None
        self._init_cap()

    def _init_cap(self):
        is_webcam = False
        try:
            cam_idx = int(self.src)
            is_webcam = True
        except (ValueError, TypeError):
            cam_idx = self.src

        if is_webcam and os.name == "nt":
            # On Windows, DirectShow with MJPG fourcc and 1-frame buffer provides instantaneous hardware frames
            self.cap = cv2.VideoCapture(cam_idx, cv2.CAP_DSHOW)
            if not self.cap.isOpened():
                self.cap = cv2.VideoCapture(cam_idx)
        else:
            self.cap = cv2.VideoCapture(cam_idx)

        if self.cap and self.cap.isOpened():
            if is_webcam:
                try:
                    self.cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*'MJPG'))
                except Exception:
                    pass
                self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
                self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
                self.cap.set(cv2.CAP_PROP_FPS, self.target_fps)
                # Eliminate Windows DirectShow webcam shutter lag (which defaults to 5-8 FPS in indoor light)
                try:
                    self.cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)
                    self.cap.set(cv2.CAP_PROP_EXPOSURE, -6)
                except Exception:
                    pass

            self.ret, self.frame = self.cap.read()
            self.running = True
            self.thread = threading.Thread(target=self._update, daemon=True)
            self.thread.start()
        else:
            self.running = False

    def _update(self):
        while self.running:
            if self.cap is None or not self.cap.isOpened():
                time.sleep(0.04)
                continue
            ret, frame = self.cap.read()
            if not ret:
                # Video file loop
                if isinstance(self.src, str) and os.path.exists(self.src):
                    self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                    continue
                else:
                    time.sleep(0.02)
                    continue
            with self.lock:
                self.ret = ret
                self.frame = frame
            # Gentle yield for video files so CPU is not pegged, without throttling pipeline
            if isinstance(self.src, str) and os.path.exists(self.src):
                time.sleep(0.005)

    def read(self):
        with self.lock:
            if self.frame is not None:
                return self.ret, self.frame
            return False, None

    def is_opened(self):
        return bool(self.running and self.cap and self.cap.isOpened())

    def release(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=0.6)
        if self.cap and self.cap.isOpened():
            self.cap.release()


class SurveillanceEngine:
    """Real-time video capture, AI detection, baseline risk scoring, and evidence persistence."""

    def __init__(self, initial_source=None):
        self.lock = threading.Lock()
        self.running = False
        self.thread = None

        # Source resolution
        if initial_source is not None:
            self.source = initial_source
        elif hasattr(settings, "VIDEO_SOURCE") and settings.VIDEO_SOURCE not in [None, ""]:
            self.source = settings.VIDEO_SOURCE
        else:
            sample_path = os.path.join(_ROOT, "gettyimages-1215957003-640_adpp.mp4")
            self.source = sample_path if os.path.exists(sample_path) else 0

        self.camera: Optional[ThreadedCamera] = None
        self.current_frame = None
        self._encoded_jpeg = None
        self.is_paused = False
        self.fps = 0
        self.frame_count = 0
        self.last_snapshot_time = 0
        self.camera_id = "cam_0"
        self._last_detections = []
        self._last_alerts = []

        # Background Alert Ingestion Worker
        self._alert_queue = queue.Queue(maxsize=150)
        self._alert_cooldowns = {}
        self._worker_running = False
        self._worker_thread = None

        # Directories
        self.output_dir = os.path.join(_ROOT, "output")
        self.snapshots_dir = os.path.join(self.output_dir, "snapshots")
        os.makedirs(self.snapshots_dir, exist_ok=True)

        # Detectors
        if DETECTION_AVAILABLE:
            logger.info("Initializing Object Detector (YOLOv8)...")
            self.object_detector = ObjectDetector()
            self.behavior_analyzer = BehaviorAnalyzer()
            self.fence_detector = FenceTamperingDetector()
            self.border_detector = BorderCrossingDetector()
            self.visualizer = Visualizer()
        else:
            self.object_detector = None
            self.behavior_analyzer = None
            self.fence_detector = None
            self.border_detector = None
            self.visualizer = None

        # Baseline & Analytics
        if BASELINE_AVAILABLE:
            self.baseline_model = BaselineModel(self.camera_id)
            if not self.baseline_model.is_bootstrapped():
                self.baseline_model.seed_synthetic_baseline()
            self.anomaly_scorer = AnomalyScorer(self.camera_id, self.baseline_model)
        else:
            self.baseline_model = None
            self.anomaly_scorer = None

        if RISK_AVAILABLE:
            self.risk_scorer = RiskScorer(self.camera_id)
        else:
            self.risk_scorer = None

        if ANALYTICS_AVAILABLE:
            self.zone_manager = ZoneManager()
            self.intrusion_detector = IntrusionDetector(self.camera_id, self.zone_manager)
            self.event_fusion = EventFusion(self.camera_id)
        else:
            self.zone_manager = None
            self.intrusion_detector = None
            self.event_fusion = None

        self._active_zones = []
        self._last_zone_fetch = 0.0
        self.active_threats_count = 0
        self._recent_events = []

    def init_capture(self, source):
        if self.camera is not None:
            self.camera.release()

        self.camera = ThreadedCamera(
            source,
            width=settings.FRAME_WIDTH,
            height=settings.FRAME_HEIGHT,
            target_fps=max(25, min(35, getattr(settings, "FPS", 30)))
        )
        if not self.camera.is_opened():
            logger.warning(f"Could not open source: {source}. Showing standby screen.")
        else:
            logger.info(f"Video capture initialized with high-speed async source: {source}")

    def switch_source(self, new_source):
        with self.lock:
            self.source = new_source
            self.fps = 0
            self._last_detections = []
            self._last_alerts = []
            self.init_capture(self.source)
            return {"status": "success", "source": str(new_source)}

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        return {"status": "success", "paused": self.is_paused}

    def start(self):
        if self.running:
            return
        self.running = True
        self._worker_running = True
        self.init_capture(self.source)
        self.thread = threading.Thread(target=self._process_loop, daemon=True)
        self.thread.start()
        self._worker_thread = threading.Thread(target=self._alert_worker, daemon=True)
        self._worker_thread.start()
        logger.info("Surveillance processing and alert worker threads started.")

    def stop(self):
        self.running = False
        self._worker_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)
        if self.camera:
            self.camera.release()
        logger.info("Surveillance processing thread stopped.")

    def _save_snapshot(self, frame, alert_type):
        now = time.time()
        if now - self.last_snapshot_time < 1.0:
            return None
        self.last_snapshot_time = now
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_type = str(alert_type).replace(" ", "_").lower()
        filename = f"{safe_type}_{timestamp}.jpg"
        filepath = os.path.join(self.snapshots_dir, filename)

        if self.visualizer:
            annotated = self.visualizer.create_snapshot(frame, {"type": alert_type, "message": alert_type})
        else:
            annotated = frame.copy()
        cv2.imwrite(filepath, annotated)
        return filename

    def _alert_worker(self):
        """Asynchronous background worker for DB persistence, snapshots, and blockchain mining."""
        while self._worker_running:
            try:
                item = self._alert_queue.get(timeout=0.4)
            except queue.Empty:
                continue

            try:
                frame_copy, alert_item, combined_detections, now_utc = item
                alert_type = alert_item.get("type", "perimeter_anomaly")
                msg = alert_item.get("message", f"Threat detected: {alert_type}")
                snapshot_file = self._save_snapshot(frame_copy, alert_type)
                snapshot_path = os.path.join(self.snapshots_dir, snapshot_file) if snapshot_file else None

                # Maintain rolling window of recent events for multi-threat correlation (60s window)
                current_time_epoch = time.time()
                self._recent_events.append({"event_type": alert_type, "timestamp": current_time_epoch})
                self._recent_events = [e for e in self._recent_events if current_time_epoch - e.get("timestamp", 0) <= 60.0]

                # Event Fusion assessment
                fusion_result = {"event_counts": {alert_type: 1}, "severity": "low", "correlated": False, "summary": ""}
                if self.event_fusion:
                    try:
                        fusion_result = self.event_fusion.fuse(self._recent_events)
                    except Exception as fe:
                        logger.warning(f"Event fusion error: {fe}")

                hour = now_utc.hour
                day_type = "weekend" if now_utc.weekday() >= 5 else "weekday"
                person_count = sum(1 for d in combined_detections if len(d) > 6 and d[6] == "person")
                vehicle_count = sum(1 for d in combined_detections if len(d) > 6 and d[6] in ["car", "truck", "motorcycle", "bus"])
                dwell_time = float(alert_item.get("dwell_time", 35.0 if alert_type == "loitering" else 15.0))
                zone_entries = float(alert_item.get("zone_entries", 2.0 if alert_type in ["intrusion", "border_crossing"] else 1.0))

                anomaly_result = {"score": 0.0, "factors": []}
                if self.anomaly_scorer:
                    try:
                        anomaly_result = self.anomaly_scorer.score(
                            observations={
                                "person_count": person_count,
                                "vehicle_count": vehicle_count,
                                "dwell_time": dwell_time,
                                "zone_entries": zone_entries,
                            },
                            events=self._recent_events,
                            hour=hour,
                            day_type=day_type,
                        )
                    except Exception as ae:
                        logger.warning(f"Anomaly scoring error: {ae}")

                # Multi-Factor Risk Calculation
                if self.risk_scorer:
                    try:
                        risk_calc = self.risk_scorer.calculate_score(
                            events=self._recent_events,
                            fusion=fusion_result,
                            anomaly=anomaly_result,
                        )
                        risk_val = float(risk_calc.get("score", 50.0))
                        contributing = risk_calc.get("contributing_factors", [])
                    except Exception as rse:
                        logger.warning(f"Risk scorer calculate error: {rse}")
                        risk_val = float(anomaly_result.get("score", 0.0)) + 40.0
                        contributing = anomaly_result.get("factors", [])
                else:
                    risk_val = float(anomaly_result.get("score", 0.0)) + 40.0
                    contributing = anomaly_result.get("factors", [])

                risk_val = min(100.0, max(15.0, risk_val))
                if not contributing:
                    contributing = [f"Direct rule match: {alert_type}", f"Entity count: {person_count} persons in sector"]


                explain_dict = (risk_calc.get("explainability") if 'risk_calc' in locals() and risk_calc else None) or {
                    "priority_tier": "CRITICAL" if risk_val >= 80 else ("HIGH" if risk_val >= 60 else "ELEVATED"),
                    "score": round(risk_val, 1),
                    "breakdown": {"rule_score": round(risk_val, 1), "baseline_component": 0.0, "fusion_bonus": 0.0},
                    "active_threats": [alert_type],
                    "reasoning": f"Prioritized alert [{alert_type}] at camera [{self.camera_id}].",
                }

                alert_id = None
                evidence_id = None
                if DB_AVAILABLE:
                    try:
                        with get_db() as db:
                            rs = RiskScore(
                                camera_id=self.camera_id,
                                timestamp=now_utc,
                                score=risk_val,
                                contributing_factors=contributing,
                                event_ids=[],
                                explainability=explain_dict,
                            )
                            db.add(rs)
                            db.flush()

                            evt = Event(
                                camera_id=self.camera_id,
                                event_type=alert_type,
                                track_id=None,
                                timestamp=now_utc,
                                zone_id=None,
                                details={"source": "video_analytics", "confidence": float(alert_item.get("confidence", 0.85))}
                            )
                            db.add(evt)
                            db.flush()

                            alert_obj = Alert(
                                risk_score_id=rs.id,
                                camera_id=self.camera_id,
                                alert_type=alert_type,
                                message=msg,
                                timestamp=now_utc,
                                status="open",
                                operator_feedback="",
                                contributing_factors=contributing,
                                risk_score_value=risk_val,
                                explainability=explain_dict,
                            )
                            db.add(alert_obj)
                            db.flush()
                            alert_id = alert_obj.id

                            # Persist ANPR VehiclePlate record if vehicle details attached
                            plate_info = alert_item.get("details", {})
                            if plate_info and plate_info.get("plate_number"):
                                vp = VehiclePlate(
                                    camera_id=self.camera_id,
                                    track_id=plate_info.get("track_id"),
                                    plate_number=plate_info["plate_number"],
                                    confidence=float(plate_info.get("confidence", 0.9)),
                                    vehicle_type=plate_info.get("vehicle_type", "car"),
                                    is_watchlist_match=bool(plate_info.get("is_watchlist_match", False)),
                                    watchlist_reason=plate_info.get("watchlist_reason"),
                                    snapshot_path=snapshot_path,
                                    timestamp=now_utc,
                                )
                                db.add(vp)

                            if snapshot_file:
                                ev = Evidence(
                                    event_id=evt.id,
                                    alert_id=alert_id,
                                    camera_id=self.camera_id,
                                    snapshot_path=snapshot_path,
                                    clip_path=None,
                                    thumbnail_path=snapshot_path,
                                    sync_status="metadata_only",
                                    created_at=now_utc
                                )
                                db.add(ev)
                                db.flush()
                                evidence_id = ev.id

                        # Phase 4 (SIH Theme): Commit alert to tamper-evident blockchain ledger
                        # Run outside DB session to prevent SQLite lock contention during PoW mining
                        if BLOCKCHAIN_AVAILABLE and _evidence_chain and alert_id:
                            try:
                                _evidence_chain.commit_alert(
                                    alert_id=alert_id,
                                    camera_id=self.camera_id,
                                    alert_type=alert_type,
                                    risk_score=risk_val,
                                    evidence_path=snapshot_path,
                                    evidence_id=evidence_id,
                                    metadata={"message": msg, "contributing_factors": contributing},
                                    timestamp=now_utc.isoformat(),
                                )
                            except Exception as be:
                                logger.warning(f"Blockchain auto-commit error: {be}")

                        # Phase 7 (Innovation 2): Bandwidth-aware sync layer queue
                        # Evidence row was persisted above; enqueue lightweight metadata push
                        if SYNC_AVAILABLE and _meta_sync and alert_id:
                            try:
                                _meta_sync.queue_event_metadata(
                                    alert_id=alert_id,
                                    camera_id=self.camera_id,
                                    event_type=alert_type,
                                    risk_score=risk_val,
                                    thumbnail_path=snapshot_path,
                                    timestamp=now_utc,
                                )
                            except Exception as se:
                                logger.warning(f"Sync queue error: {se}")

                    except Exception as ex:
                        logger.error(f"Error persisting live threat: {ex}")

                alert_payload = {
                    "id": alert_id or int(time.time() * 1000),
                    "camera_id": self.camera_id,
                    "alert_type": alert_type,
                    "type": alert_type,
                    "message": msg,
                    "confidence": round(float(alert_item.get("confidence", 0.85)), 2),
                    "timestamp": now_utc.isoformat(),
                    "snapshot": snapshot_file,
                    "risk_score": risk_val,
                    "contributing_factors": contributing,
                    "explainability": explain_dict,
                    "plate_number": alert_item.get("details", {}).get("plate_number"),
                    "sync_status": "metadata_only",
                    "status": "open",
                }

                with _alert_lock:
                    _legacy_alerts.append(alert_payload)
                    if len(_legacy_alerts) > MAX_LEGACY:
                        _legacy_alerts.pop(0)

                if _event_loop:
                    asyncio.run_coroutine_threadsafe(_broadcast(alert_payload), _event_loop)
            except Exception as e:
                logger.error(f"Alert worker error: {e}")
            finally:
                self._alert_queue.task_done()

    def _process_loop(self):
        prev_time = time.perf_counter()
        target_fps = max(25, min(35, getattr(settings, "FPS", 30)))
        target_frame_time = 1.0 / target_fps

        while self.running:
            if self.is_paused:
                time.sleep(0.04)
                continue

            loop_start = time.perf_counter()

            if self.camera is None or not self.camera.is_opened():
                placeholder = np.zeros((settings.FRAME_HEIGHT, settings.FRAME_WIDTH, 3), dtype=np.uint8)
                cv2.putText(placeholder, "STANDBY / NO SENSOR SIGNAL", (settings.FRAME_WIDTH//2 - 190, settings.FRAME_HEIGHT//2),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 240, 255), 2)
                cv2.putText(placeholder, f"Source: {self.source}", (settings.FRAME_WIDTH//2 - 130, settings.FRAME_HEIGHT//2 + 40),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (180, 180, 180), 1)
                ret_jpg, jpeg_buf = cv2.imencode('.jpg', placeholder, [cv2.IMWRITE_JPEG_QUALITY, 70])
                jpeg_bytes = jpeg_buf.tobytes() if ret_jpg else None
                with self.lock:
                    self.current_frame = placeholder
                    self._encoded_jpeg = jpeg_bytes
                time.sleep(0.08)
                continue

            ret, frame = self.camera.read()
            if not ret or frame is None:
                time.sleep(0.004)
                continue

            if frame.shape[1] != settings.FRAME_WIDTH or frame.shape[0] != settings.FRAME_HEIGHT:
                frame = cv2.resize(frame, (settings.FRAME_WIDTH, settings.FRAME_HEIGHT))

            self.frame_count += 1

            # Refresh active zones cache periodically (every 4 seconds) without blocking SQLite
            now_mono = time.time()
            if self.zone_manager and (now_mono - self._last_zone_fetch > 4.0 or not self._active_zones):
                self._last_zone_fetch = now_mono
                try:
                    self._active_zones = self.zone_manager.get_zones(self.camera_id)
                except Exception as ze:
                    logger.debug(f"Could not load active zones: {ze}")

            combined_detections = []
            frame_alerts = []

            if DETECTION_AVAILABLE and self.object_detector:
                # Alternating high-speed inference: run YOLO + BYTETracker on even frames, reuse detections on odd frames for smooth 25-30+ FPS
                if self.frame_count % 2 == 0 or not self._last_detections:
                    combined_detections = self.object_detector.detect_and_track(frame, camera_id=self.camera_id)
                    self._last_detections = combined_detections

                    # 1. Restricted zone intrusion detection
                    intrusion_alerts = []
                    if self.intrusion_detector and self._active_zones:
                        for d in combined_detections:
                            x1, y1, x2, y2 = d[:4]
                            foot_point = ((x1 + x2) // 2, y2)
                            track_id = d[7] if len(d) > 7 and d[7] >= 0 else 0
                            ev = self.intrusion_detector.check(
                                track_id=track_id,
                                bottom_center=foot_point,
                                zones=self._active_zones,
                                timestamp=datetime.utcnow(),
                                persist=False,
                                bbox=(x1, y1, x2, y2),
                            )
                            if ev:
                                intrusion_alerts.append(ev)

                    # 2. Behavior analysis (loitering, crawling)
                    behavior_alerts = self.behavior_analyzer.update(combined_detections, frame) if self.behavior_analyzer else []

                    # 3. Perimeter fence tampering
                    tampering_alerts = self.fence_detector.detect(frame) if self.fence_detector else []

                    # 4. Virtual border crossing
                    border_alerts = self.border_detector.detect(combined_detections, frame) if self.border_detector else []

                    # 5. ANPR vehicle reconnaissance on detected vehicle bounding boxes
                    anpr_alerts = []
                    if ANPR_AVAILABLE and anpr_engine:
                        vh, vw = frame.shape[:2]
                        for d in combined_detections:
                            cname = d[6]
                            if cname in ['car', 'truck', 'bus', 'motorcycle']:
                                vx1, vy1, vx2, vy2 = d[:4]
                                v_track = d[7] if len(d) > 7 and d[7] >= 0 else None
                                cx1, cy1 = max(0, vx1), max(0, vy1)
                                cx2, cy2 = min(vw, vx2), min(vh, vy2)
                                if cx2 > cx1 and cy2 > cy1:
                                    vcrop = frame[cy1:cy2, cx1:cx2]
                                    plate_res = anpr_engine.recognize_vehicle_plate(vcrop, self.camera_id, v_track, cname)
                                    if plate_res.get("is_watchlist_match"):
                                        anpr_alerts.append({
                                            "type": "watchlist_vehicle",
                                            "message": f"WATCHLIST VEHICLE [{plate_res['plate_number']}]: {plate_res.get('watchlist_reason', '')}",
                                            "confidence": plate_res.get("confidence", 0.9),
                                            "bbox": (vx1, vy1, vx2, vy2),
                                            "details": plate_res,
                                        })

                    frame_alerts = intrusion_alerts + behavior_alerts + tampering_alerts + border_alerts + anpr_alerts
                    self._last_alerts = frame_alerts
                else:
                    combined_detections = self._last_detections
                    frame_alerts = self._last_alerts

            # Fast enqueue to background worker with 2.0s cooldown per alert type
            now_alert_t = time.time()
            for alert_item in frame_alerts:
                atype = alert_item.get("type", "perimeter_anomaly")
                last_t = self._alert_cooldowns.get(atype, 0)
                if now_alert_t - last_t >= 2.0:
                    self._alert_cooldowns[atype] = now_alert_t
                    try:
                        self._alert_queue.put_nowait((frame.copy(), alert_item, list(combined_detections), datetime.utcnow()))
                    except queue.Full:
                        pass

            # Visualisation overlay
            annotated_frame = frame.copy()
            if self.visualizer:
                if self._active_zones:
                    annotated_frame = self.visualizer.draw_zones(annotated_frame, self._active_zones)
                if combined_detections:
                    annotated_frame = self.visualizer.draw_detections(annotated_frame, combined_detections)
                if hasattr(settings, "BORDER_LINES") and settings.BORDER_LINES:
                    annotated_frame = self.visualizer.draw_border_lines(annotated_frame, settings.BORDER_LINES)
                annotated_frame = self.visualizer.draw_alerts(annotated_frame, frame_alerts)
                annotated_frame = self.visualizer.add_info_overlay(annotated_frame, len(combined_detections))

            # Exponential moving average (EMA) FPS for rock-solid stability
            curr_time = time.perf_counter()
            dt = curr_time - prev_time
            prev_time = curr_time
            if 0.001 < dt < 1.0:
                instant_fps = 1.0 / dt
                if self.fps <= 0:
                    self.fps = round(instant_fps, 1)
                else:
                    self.fps = round(0.85 * self.fps + 0.15 * instant_fps, 1)

            # Pre-encode JPEG for fast non-blocking streaming
            ret_jpg, jpeg_buf = cv2.imencode('.jpg', annotated_frame, [cv2.IMWRITE_JPEG_QUALITY, 72])
            jpeg_bytes = jpeg_buf.tobytes() if ret_jpg else None

            with self.lock:
                self.current_frame = annotated_frame
                self._encoded_jpeg = jpeg_bytes
                self.active_threats_count = len(frame_alerts)

            # Frame rate regulation (ensures smooth real-time 30 FPS)
            elapsed = time.perf_counter() - loop_start
            sleep_time = max(0.001, target_frame_time - elapsed)
            time.sleep(sleep_time)


engine = SurveillanceEngine()
camera_manager.set_engine(engine)
if _evidence_chain:
    _evidence_dossier_gen.blockchain_ledger = _evidence_chain


# ── App Lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _event_loop
    _event_loop = asyncio.get_running_loop()

    if DB_AVAILABLE:
        try:
            os.makedirs(settings.DATA_DIR, exist_ok=True)
            init_db()
            logger.info("Database initialised.")
        except Exception as e:
            logger.error(f"DB init failed: {e}")

    engine.start()

    yield

    engine.stop()


app = FastAPI(
    title="Border Surveillance System API",
    description="Intelligent AI Video Analytics & Blockchain Platform",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Static Web Dashboard Mount ────────────────────────────────────────────────

_WEB_DIR = os.path.join(_ROOT, "web")
if os.path.isdir(_WEB_DIR):
    app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")

@app.get("/")
def serve_root():
    index_file = os.path.join(_WEB_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"status": "Dashboard frontend under construction."})

@app.get("/api/map_file")
def get_map_file():
    map_path = os.path.join(_ROOT, "output", "detection_map.html")
    if os.path.exists(map_path):
        return FileResponse(map_path)
    return JSONResponse({"status": "Map not generated yet"}, status_code=404)


# ── WebSocket Broadcast Helper ───────────────────────────────────────────────

async def _broadcast(payload: dict):
    dead = []
    for ws in list(active_connections):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in active_connections:
            active_connections.remove(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "db": DB_AVAILABLE,
        "blockchain": BLOCKCHAIN_AVAILABLE,
        "sync": SYNC_AVAILABLE,
        "fps": engine.fps,
    }


# ── Live Video Streaming & Source Controls ───────────────────────────────────

def _generate_video_stream():
    """Generator for high-speed live MJPEG video stream."""
    last_jpeg = None

    while True:
        with engine.lock:
            jpeg_bytes = engine._encoded_jpeg

        if jpeg_bytes is None:
            time.sleep(0.02)
            continue

        if jpeg_bytes is not last_jpeg:
            last_jpeg = jpeg_bytes
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + jpeg_bytes + b'\r\n')
            time.sleep(0.002)
        else:
            time.sleep(0.005)

@app.get("/api/video_feed")
def video_feed():
    """Live MJPEG video stream with YOLOv8 & HUD overlay."""
    return StreamingResponse(
        _generate_video_stream(),
        media_type="multipart/x-mixed-replace; boundary=frame"
    )

@app.post("/api/source")
def switch_source(payload: SourcePayload):
    src = payload.source.strip()
    if src == "webcam":
        src = 0
    elif src in ("sample", "sample_1", "sample1"):
        src = getattr(settings, "SAMPLE_VIDEO_1", os.path.join(_ROOT, "gettyimages-1215957003-640_adpp.mp4"))
    elif src in ("sample_2", "sample2", "15690486_1920_1080_25fps.mp4"):
        src = getattr(settings, "SAMPLE_VIDEO_2", os.path.join(_ROOT, "15690486_1920_1080_25fps.mp4"))
    elif os.path.exists(src):
        src = src
    elif os.path.exists(os.path.join(_ROOT, src)):
        src = os.path.join(_ROOT, src)
    return engine.switch_source(src)

@app.post("/api/control/pause")
def toggle_pause():
    return engine.toggle_pause()


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    offset: int = 0,
    alert_type: Optional[str] = None,
    status: Optional[str] = None,
    camera_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    if not DB_AVAILABLE:
        with _alert_lock:
            return {"total": len(_legacy_alerts), "alerts": _legacy_alerts[offset: offset + limit]}

    with get_db() as db:
        q = db.query(Alert).order_by(desc(Alert.timestamp))
        if alert_type:
            q = q.filter(Alert.alert_type == alert_type)
        if status:
            q = q.filter(Alert.status == status)
        if camera_id:
            q = q.filter(Alert.camera_id == camera_id)
        if start_time:
            try:
                q = q.filter(Alert.timestamp >= datetime.fromisoformat(start_time))
            except ValueError:
                pass
        if end_time:
            try:
                q = q.filter(Alert.timestamp <= datetime.fromisoformat(end_time))
            except ValueError:
                pass
        total = q.count()
        rows = q.offset(offset).limit(limit).all()
        alerts = [_alert_to_dict(r) for r in rows]
    return {"total": total, "alerts": alerts}


@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 10):
    if not DB_AVAILABLE:
        with _alert_lock:
            return _legacy_alerts[-limit:]
    with get_db() as db:
        rows = db.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()
        return [_alert_to_dict(r) for r in rows]


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        row = db.query(Alert).filter(Alert.id == alert_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return _alert_to_dict(row)


@app.post("/api/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: int, body: DismissRequest = Body(default=DismissRequest())):
    """
    Mark alert as dismissed.
    - Triggers baseline recalibration (false-positive learning)
    - Records dismissal audit event on the blockchain (immutable)
    """
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.status = "dismissed"
        alert.operator_feedback = body.feedback or ""
        camera_id = alert.camera_id
        alert_ts = alert.timestamp

    # Trigger baseline feedback loop outside the active DB context to avoid nested SQLite lock
    recalibrated = 0
    if FEEDBACK_AVAILABLE:
        try:
            fl = FeedbackLoop(camera_id)
            fl.record_dismissal(camera_id, alert_ts)
            recalibrated = fl.recalibrate(camera_id)
        except Exception as e:
            logger.warning(f"Baseline recalibration error: {e}")

    # Record dismissal on blockchain (immutable audit trail)
    blockchain_tx = {}
    if BLOCKCHAIN_AVAILABLE and _evidence_chain:
        try:
            blockchain_tx = _evidence_chain.record_audit(
                action="dismiss",
                entity_id=alert_id,
                details={"feedback": body.feedback or "", "camera_id": camera_id},
            )
        except Exception as e:
            logger.warning(f"Blockchain audit record failed: {e}")

    return {
        "status": "dismissed",
        "alert_id": alert_id,
        "rows_recalibrated": recalibrated,
        "blockchain": blockchain_tx or None,
    }


@app.post("/api/alerts/{alert_id}/confirm")
async def confirm_alert(alert_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.status = "confirmed"
        camera_id = alert.camera_id

    blockchain_tx = {}
    if BLOCKCHAIN_AVAILABLE and _evidence_chain:
        try:
            blockchain_tx = _evidence_chain.record_audit(
                action="confirm",
                entity_id=alert_id,
                details={"camera_id": camera_id},
            )
        except Exception as e:
            logger.warning(f"Blockchain audit record failed: {e}")

    return {"status": "confirmed", "alert_id": alert_id, "blockchain": blockchain_tx or None}


# ── Events ────────────────────────────────────────────────────────────────────

@app.get("/api/events")
async def get_events(
    camera_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        q = db.query(Event).order_by(desc(Event.timestamp))
        if camera_id:
            q = q.filter(Event.camera_id == camera_id)
        if event_type:
            q = q.filter(Event.event_type == event_type)
        total = q.count()
        rows = q.offset(offset).limit(limit).all()
        events_data = [_event_to_dict(r) for r in rows]
    return {
        "total": total,
        "events": events_data,
    }


# ── Risk Scores ───────────────────────────────────────────────────────────────

@app.get("/api/risk-scores")
async def get_risk_scores(
    camera_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        q = db.query(RiskScore).order_by(desc(RiskScore.timestamp))
        if camera_id:
            q = q.filter(RiskScore.camera_id == camera_id)
        total = q.count()
        rows = q.offset(offset).limit(limit).all()
        scores_data = [_risk_to_dict(r) for r in rows]
    return {
        "total": total,
        "risk_scores": scores_data,
    }


# ── Zones ─────────────────────────────────────────────────────────────────────

@app.get("/api/zones")
@app.get("/api/zones/{camera_id}")
def get_zones(camera_id: Optional[str] = None):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        q = db.query(Zone).filter(Zone.is_active == True)
        if camera_id:
            q = q.filter(Zone.camera_id == camera_id)
        rows = q.all()
        return [_zone_to_dict(r) for r in rows]


# ── Analytics Summary ─────────────────────────────────────────────────────────

@app.get("/api/analytics/summary")
def get_analytics_summary():
    if not DB_AVAILABLE:
        return {
            "total_alerts": len(_legacy_alerts),
            "active_threats": engine.active_threats_count,
            "event_breakdown": {},
            "fps": engine.fps,
        }
    with get_db() as db:
        total_alerts = db.query(Alert).count()
        open_alerts = db.query(Alert).filter(Alert.status == "open").count()
        confirmed_alerts = db.query(Alert).filter(Alert.status == "confirmed").count()
        dismissed_alerts = db.query(Alert).filter(Alert.status == "dismissed").count()

        event_types = db.query(Event.event_type, func.count(Event.id)).group_by(Event.event_type).all()
        event_breakdown = {t: c for t, c in event_types}

        total_zones = db.query(Zone).filter(Zone.is_active == True).count()
        avg_risk = db.query(func.avg(RiskScore.score)).scalar() or 0.0

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "confirmed_alerts": confirmed_alerts,
        "dismissed_alerts": dismissed_alerts,
        "active_threats": engine.active_threats_count,
        "event_breakdown": event_breakdown,
        "total_zones": total_zones,
        "avg_risk_score": round(float(avg_risk), 1),
        "fps": engine.fps,
        "camera_id": engine.camera_id,
        "source": str(engine.source),
    }


@app.post("/api/zones")
async def create_zone(payload: ZoneCreate):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        zone = Zone(
            camera_id=payload.camera_id,
            name=payload.name,
            polygon_points=payload.polygon_points,
            is_active=True,
        )
        db.add(zone)
        db.flush()
        res = _zone_to_dict(zone)
    if engine:
        engine._last_zone_fetch = 0.0
    return res


@app.delete("/api/zones/{zone_id}")
async def delete_zone(zone_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        zone = db.query(Zone).filter(Zone.id == zone_id).first()
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        zone.is_active = False
    if engine:
        engine._last_zone_fetch = 0.0
    return {"deleted": zone_id}


# ── Baseline ──────────────────────────────────────────────────────────────────

@app.get("/api/baseline/{camera_id}")
async def get_baseline(camera_id: str):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        rows = db.query(BaselineStat).filter(BaselineStat.camera_id == camera_id).all()
        stats = [_baseline_to_dict(r) for r in rows]

    recalibration_summary = {}
    if FEEDBACK_AVAILABLE and stats:
        try:
            fl = FeedbackLoop(camera_id)
            recalibration_summary = fl.get_recalibration_summary(camera_id)
        except Exception:
            pass

    return {
        "camera_id": camera_id,
        "bootstrapped": len(stats) > 0,
        "stats": stats,
        "recalibration": recalibration_summary,
    }

@app.post("/api/baseline/{camera_id}/seed")
async def seed_baseline_endpoint(camera_id: str):
    if not BASELINE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Baseline engine not available")
    bm = BaselineModel(camera_id)
    bm.seed_synthetic_baseline()
    return {"status": "seeded", "camera_id": camera_id}


# ── Sync Status ───────────────────────────────────────────────────────────────

@app.get("/api/sync/status")
async def get_sync_status(camera_id: Optional[str] = None):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        q = db.query(Evidence)
        if camera_id:
            q = q.filter(Evidence.camera_id == camera_id)
        total = q.count()
        metadata_only = q.filter(Evidence.sync_status == "metadata_only").count()
        full_synced = q.filter(Evidence.sync_status == "full_synced").count()
    queue_depth = _meta_sync.get_queue_depth() if _meta_sync else 0
    return {
        "total": total,
        "metadata_only": metadata_only,
        "full_synced": full_synced,
        "pending_queue": queue_depth,
    }


@app.post("/api/sync/simulate-poor-connectivity")
async def toggle_poor_connectivity(request: Request, enabled: Optional[bool] = None):
    if not SYNC_AVAILABLE or not _meta_sync:
        raise HTTPException(status_code=503, detail="Sync layer not available")
    is_enabled = True
    if enabled is not None:
        is_enabled = enabled
    else:
        try:
            body = await request.json()
            is_enabled = bool(body.get("enabled", True))
        except Exception:
            pass
    _meta_sync.simulate_poor_connectivity(is_enabled)
    return {"simulating_poor_connectivity": is_enabled}


# ── Evidence & Snapshots ──────────────────────────────────────────────────────

@app.get("/api/evidence/{alert_id}")
async def get_evidence_for_alert(alert_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="DB not available")
    with get_db() as db:
        rows = db.query(Evidence).filter(Evidence.alert_id == alert_id).all()
        return [_evidence_to_dict(r) for r in rows]



@app.get("/api/snapshots/{filename}")
@app.get("/api/evidence/snapshot/{filename}")
async def serve_snapshot(filename: str):
    path = os.path.join(engine.snapshots_dir, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return FileResponse(path)


# ── Statistics ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)
    if not DB_AVAILABLE:
        with _alert_lock:
            return {
                "status": "ONLINE",
                "fps": engine.fps,
                "active_threats": engine.active_threats_count,
                "total_alerts": len(_legacy_alerts),
                "open_alerts": len(_legacy_alerts),
                "db_available": False,
            }

    with get_db() as db:
        total_alerts = db.query(Alert).count()
        open_alerts = db.query(Alert).filter(Alert.status == "open").count()
        alerts_24h = db.query(Alert).filter(Alert.timestamp >= day_ago).count()
        total_events = db.query(Event).count()
        events_24h = db.query(Event).filter(Event.timestamp >= day_ago).count()
        alert_type_counts = dict(
            db.query(Alert.alert_type, func.count(Alert.id))
            .group_by(Alert.alert_type)
            .all()
        )
        avg_risk = db.query(func.avg(RiskScore.score)).scalar() or 0.0
        sync_summary = {}
        if SYNC_AVAILABLE and _evidence_queue:
            try:
                sync_summary = _evidence_queue.get_sync_status_summary()
            except Exception:
                pass

    return {
        "status": "ONLINE",
        "fps": engine.fps,
        "active_threats": engine.active_threats_count,
        "db_available": True,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "alerts_last_24h": alerts_24h,
        "total_events": total_events,
        "events_last_24h": events_24h,
        "alerts_by_type": alert_type_counts,
        "avg_risk_score": round(avg_risk, 1),
        "sync": sync_summary,
        "active_ws_connections": len(active_connections),
        "source": str(engine.source),
    }


# ── AI Investigation Assistant ────────────────────────────────────────────────

@app.post("/api/assistant/query")
def assistant_query(body: AssistantQuery):
    if not ASSISTANT_AVAILABLE or not _assistant:
        return {
            "answer": "AI assistant not available. Please verify GEMINI_API_KEY in your .env file.",
            "sources": [],
            "grounded": False
        }
    try:
        result = _assistant.query(body.question)
        if not result or not result.get("answer"):
            result = {
                "answer": "No specific intelligence data found for this query in the surveillance database.",
                "sources": [],
                "grounded": False
            }
        return result
    except Exception as e:
        logger.error(f"Assistant query error: {e}")
        return {
            "answer": f"Intelligence query temporarily unavailable: {str(e)}",
            "sources": [],
            "grounded": False
        }


@app.get("/api/assistant/report/{alert_id}")
@app.post("/api/assistant/report/{alert_id}")
def draft_incident_report(alert_id: int):
    if not ASSISTANT_AVAILABLE or not _assistant:
        return {
            "report_text": "AI assistant unavailable. Set GEMINI_API_KEY in .env.",
            "alert_id": alert_id,
            "generated_at": datetime.utcnow().isoformat(),
            "llm_used": False
        }
    try:
        result = _assistant.draft_incident_report(alert_id)
        return result
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return {
            "report_text": f"Error generating narrative report for Alert #{alert_id}: {str(e)}",
            "alert_id": alert_id,
            "generated_at": datetime.utcnow().isoformat(),
            "llm_used": False
        }


# ── Blockchain Evidence Ledger ────────────────────────────────────────────────

@app.get("/api/blockchain/status")
async def blockchain_status():
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        return {"available": False, "message": "Blockchain module not initialised"}
    stats = _evidence_chain.get_stats()
    stats["available"] = True
    return stats


@app.get("/api/blockchain/verify-chain")
async def blockchain_verify_chain():
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    return _evidence_chain.verify_chain()


@app.get("/api/blockchain/ledger")
async def blockchain_ledger(n: int = 20):
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    return {"blocks": _evidence_chain.get_recent_blocks(n)}


@app.post("/api/blockchain/reset")
async def blockchain_reset():
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    stats = _evidence_chain.reset_chain()
    return {"status": "reset", **stats}


@app.get("/api/blockchain/verify/{alert_id}")
async def blockchain_verify_alert(alert_id: int):
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert_dict = _alert_to_dict(alert)
        ev = db.query(Evidence).filter(Evidence.alert_id == alert_id).first()
        ev_id = ev.id if ev else None
        snap_path = ev.snapshot_path if ev else None
        thumb_path = ev.thumbnail_path if ev else None

    result = _evidence_chain.verify_alert(alert_id, alert_dict)

    # Also verify physical optical evidence snapshot if committed
    if ev_id:
        ev_block = _evidence_chain.get_record_info(f"evidence_{ev_id}")
        if ev_block:
            ev_verify = _evidence_chain.verify_evidence(ev_id, snap_path, thumb_path)
            result["evidence_verification"] = ev_verify
            if not ev_verify.get("verified"):
                result["verified"] = False
                if not os.path.exists(snap_path or "") and not os.path.exists(thumb_path or ""):
                    result["message"] = "🚨 TAMPERED — Alert record valid, but evidence snapshot file was DELETED or missing from storage!"
                else:
                    result["message"] = "🚨 TAMPERED — Evidence snapshot image was modified after blockchain commitment!"
    return result


@app.post("/api/blockchain/commit/{alert_id}")
async def blockchain_commit_alert(alert_id: int):
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert_dict = _alert_to_dict(alert)
        ev = db.query(Evidence).filter(Evidence.alert_id == alert_id).first()
        ev_id = ev.id if ev else None
        snap_path = ev.snapshot_path if ev else None
        thumb_path = ev.thumbnail_path if ev else None

    result = _evidence_chain.record_alert(alert_id, alert_dict)
    if ev_id and snap_path:
        _evidence_chain.record_evidence(ev_id, alert_id, snap_path, thumb_path)
    return {"committed": True, **result}


@app.post("/api/blockchain/commit-all")
async def blockchain_commit_all_alerts():
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain or not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Blockchain or DB not available")
    with get_db() as db:
        alerts = db.query(Alert).all()
        alert_items = []
        for a in alerts:
            ev = db.query(Evidence).filter(Evidence.alert_id == a.id).first()
            alert_items.append({
                "id": a.id,
                "dict": _alert_to_dict(a),
                "ev_id": ev.id if ev else None,
                "snap_path": ev.snapshot_path if ev else None,
                "thumb_path": ev.thumbnail_path if ev else None,
            })

    committed, skipped = 0, 0
    for item in alert_items:
        try:
            a_id = item["id"]
            existing = _evidence_chain.get_record_info(f"alert_{a_id}")
            if existing:
                skipped += 1
            else:
                _evidence_chain.record_alert(a_id, item["dict"])
                committed += 1

            if item["ev_id"] and not _evidence_chain.get_record_info(f"evidence_{item['ev_id']}"):
                _evidence_chain.record_evidence(item["ev_id"], a_id, item["snap_path"], item["thumb_path"])
        except Exception as e:
            logger.warning(f"Failed to commit alert {item['id']}: {e}")

    return {
        "committed": committed,
        "skipped_already_on_chain": skipped,
        "total_alerts": len(alert_items),
        "message": f"Committed {committed} new records to blockchain ({skipped} already sealed)."
    }

_tamper_backups: Dict[int, Dict[str, Any]] = {}

@app.post("/api/blockchain/simulate-tamper/{alert_id}")
async def blockchain_simulate_tamper(alert_id: int):
    if not BLOCKCHAIN_AVAILABLE or not _evidence_chain:
        raise HTTPException(status_code=503, detail="Blockchain not available")
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Save original state for clean restoration
        if alert_id not in _tamper_backups:
            _tamper_backups[alert_id] = {
                "message": alert.message,
                "risk_score_value": alert.risk_score_value,
                "alert_type": alert.alert_type,
            }

        orig_msg = alert.message
        orig_risk = alert.risk_score_value

        # Alter sensitive fields in database
        alert.message = f"[UNAUTHORIZED MUTATION] Clearance Verified - Friendly Patrol (Original: {orig_msg})"
        alert.risk_score_value = 5.0
        db.commit()

    logger.warning(f"Simulated DB tamper attack executed on Alert #{alert_id}")
    return {
        "status": "tampered",
        "alert_id": alert_id,
        "original_message": orig_msg,
        "original_risk": orig_risk,
        "tampered_message": alert.message,
        "tampered_risk": alert.risk_score_value,
        "message": "⚠️ Simulated database modification applied! Verifying this record will now trigger a cryptographic tamper alert."
    }


@app.post("/api/blockchain/restore-tamper/{alert_id}")
async def blockchain_restore_tamper(alert_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    if alert_id not in _tamper_backups:
        raise HTTPException(status_code=400, detail="No tamper backup found for this alert (it was not modified via simulation)")

    backup = _tamper_backups[alert_id]
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert.message = backup["message"]
        alert.risk_score_value = backup["risk_score_value"]
        alert.alert_type = backup["alert_type"]
        db.commit()

    del _tamper_backups[alert_id]
    logger.info(f"Restored Alert #{alert_id} from tamper simulation backup")
    return {
        "status": "restored",
        "alert_id": alert_id,
        "restored_message": alert.message,
        "restored_risk": alert.risk_score_value,
        "message": "✅ Database record restored to pristine state. Cryptographic verification will now pass."
    }




# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        if DB_AVAILABLE:
            with get_db() as db:
                recent = db.query(Alert).order_by(desc(Alert.timestamp)).limit(10).all()
                for a in reversed(recent):
                    await websocket.send_json(_alert_to_dict(a))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WS closed: {e}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.post("/api/ingest/metadata")
async def ingest_metadata(payload: Dict[str, Any] = Body(...)):
    await _broadcast(payload)
    return {"received": True}


# ── Automatic Number Plate Recognition (ANPR / ALPR) ─────────────────────────

@app.get("/api/anpr/plates")
async def get_anpr_plates(limit: int = 50, camera_id: Optional[str] = None):
    if not DB_AVAILABLE:
        return {"total": 0, "plates": []}
    with get_db() as db:
        q = db.query(VehiclePlate).order_by(desc(VehiclePlate.timestamp))
        if camera_id and camera_id != "all":
            q = q.filter(VehiclePlate.camera_id == camera_id)
        rows = q.limit(limit).all()
        return {"total": len(rows), "plates": [r.to_dict() for r in rows]}

@app.get("/api/anpr/watchlist")
async def get_anpr_watchlist():
    if not ANPR_AVAILABLE or not anpr_engine:
        return {"watchlist": {}}
    return {"watchlist": anpr_engine.get_watchlist()}

@app.post("/api/anpr/watchlist")
async def add_anpr_watchlist(payload: WatchlistAddRequest, user: dict = Depends(get_current_user)):
    if not ANPR_AVAILABLE or not anpr_engine:
        raise HTTPException(status_code=503, detail="ANPR engine unavailable")
    res = anpr_engine.add_to_watchlist(payload.plate_number, payload.reason, payload.severity, payload.agency)
    log_audit_event(
        user_callsign=user.get("callsign", "Operator"),
        role=user.get("role", "OPERATOR"),
        action="WATCHLIST_ADD",
        resource=f"Plate {res['plate_number']}",
        details=res,
    )
    return {"status": "success", "entry": res}

@app.get("/api/anpr/lookup/{plate_number}")
async def lookup_plate(plate_number: str):
    if not ANPR_AVAILABLE or not anpr_engine:
        raise HTTPException(status_code=503, detail="ANPR engine unavailable")
    norm = anpr_engine.normalize_plate(plate_number)
    is_hit, hit_meta = anpr_engine.is_watchlist_match(norm)
    history = []
    if DB_AVAILABLE:
        with get_db() as db:
            rows = db.query(VehiclePlate).filter(VehiclePlate.plate_number == norm).order_by(desc(VehiclePlate.timestamp)).all()
            history = [r.to_dict() for r in rows]
    return {
        "plate_number": norm,
        "is_watchlist_match": is_hit,
        "watchlist_details": hit_meta,
        "sightings_count": len(history),
        "history": history,
    }


# ── Automatic Evidence Dossiers & Reports ─────────────────────────────────────

@app.get("/api/evidence/dossier/{alert_id}")
async def get_evidence_dossier(alert_id: int):
    dossier = _evidence_dossier_gen.generate_dossier(alert_id)
    if "error" in dossier:
        raise HTTPException(status_code=404, detail=dossier["error"])
    return dossier

@app.get("/api/evidence/dossier/{alert_id}/html")
async def get_evidence_dossier_html(alert_id: int, user: dict = Depends(get_current_user)):
    html_content = _evidence_dossier_gen.generate_html_dossier(alert_id)
    log_audit_event(
        user_callsign=user.get("callsign", "Analyst"),
        role=user.get("role", "ANALYST"),
        action="DOSSIER_EXPORT",
        resource=f"Alert #{alert_id}",
    )
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)


# ── Centralized Historical Search & Investigation Hub ─────────────────────────

@app.get("/api/investigation/search")
async def investigation_search(
    query: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    camera_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    min_risk: Optional[float] = None,
    plate_number: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    if not DB_AVAILABLE:
        return {"total": 0, "results": []}

    with get_db() as db:
        q = db.query(Alert).order_by(desc(Alert.timestamp))

        if camera_id and camera_id != "all":
            q = q.filter(Alert.camera_id == camera_id)
        if alert_type and alert_type != "all":
            q = q.filter(Alert.alert_type == alert_type)
        if status and status != "all":
            q = q.filter(Alert.status == status)
        if min_risk is not None:
            q = q.filter(Alert.risk_score_value >= min_risk)
        if start_time:
            try:
                q = q.filter(Alert.timestamp >= datetime.fromisoformat(start_time))
            except Exception:
                pass
        if end_time:
            try:
                q = q.filter(Alert.timestamp <= datetime.fromisoformat(end_time))
            except Exception:
                pass
        if query:
            search_str = f"%{query}%"
            q = q.filter((Alert.message.ilike(search_str)) | (Alert.alert_type.ilike(search_str)))

        total = q.count()
        alerts = q.offset(offset).limit(limit).all()

        results = []
        for a in alerts:
            ad = _alert_to_dict(a)
            ev = db.query(Evidence).filter(Evidence.alert_id == a.id).first()
            ad["snapshot_path"] = ev.snapshot_path if ev else None

            if a.camera_id:
                vp = db.query(VehiclePlate).filter(VehiclePlate.camera_id == a.camera_id).order_by(desc(VehiclePlate.timestamp)).first()
                ad["plate_number"] = vp.plate_number if vp else None
                ad["is_watchlist_match"] = vp.is_watchlist_match if vp else False

            if plate_number:
                norm_search = anpr_engine.normalize_plate(plate_number) if anpr_engine else plate_number.upper()
                if ad.get("plate_number") != norm_search:
                    continue
            results.append(ad)

        return {"total": total, "results": results}

@app.get("/api/investigation/incident/{alert_id}")
async def investigation_incident(alert_id: int):
    if not DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    with get_db() as db:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Incident not found")

        ad = _alert_to_dict(alert)
        ev = db.query(Evidence).filter(Evidence.alert_id == alert_id).first()
        ad["evidence"] = ev.to_dict() if ev else None

        # Timeline of surrounding events (+/- 3 minutes)
        timeline = []
        if alert.timestamp:
            t0 = alert.timestamp - timedelta(minutes=3)
            t1 = alert.timestamp + timedelta(minutes=3)
            events = db.query(Event).filter(Event.camera_id == alert.camera_id, Event.timestamp >= t0, Event.timestamp <= t1).order_by(Event.timestamp.asc()).all()
            timeline = [e.to_dict() for e in events]

        plates = db.query(VehiclePlate).filter(VehiclePlate.camera_id == alert.camera_id).order_by(desc(VehiclePlate.timestamp)).limit(5).all()

        bc_status = {"verified": False}
        if BLOCKCHAIN_AVAILABLE and _evidence_chain:
            try:
                snap_p = ev.snapshot_path if ev else None
                thumb_p = ev.thumbnail_path if ev else None
                ev_id = ev.id if ev else alert_id
                bc_status = _evidence_chain.verify_evidence(ev_id, snap_p, thumb_p)
            except Exception:
                pass

        return {
            "alert": ad,
            "timeline": timeline,
            "plates": [p.to_dict() for p in plates],
            "blockchain": bc_status,
        }


# ── Role-Based Access Control (RBAC) & Authentication ─────────────────────────

@app.post("/api/auth/login")
async def auth_login(payload: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = authenticate_user(payload.username, payload.password)
    if not user:
        log_audit_event(
            user_callsign=payload.username or "UNKNOWN",
            role="UNAUTHENTICATED",
            action="LOGIN_FAILED",
            resource="C2 Command Platform",
            details={"attempted_username": payload.username, "reason": "Invalid credentials"},
            ip_address=client_ip,
        )
        raise HTTPException(status_code=401, detail="Invalid tactical credentials or unauthorized clearance key.")

    token = create_access_token(user)
    log_audit_event(
        user_callsign=user["callsign"],
        role=user["role"],
        action="USER_LOGIN",
        resource="C2 Command Platform",
        details={"username": user.get("username"), "station": user.get("station"), "clearance": user.get("clearance")},
        ip_address=client_ip,
    )
    return {"token": token, "user": user, "status": "authenticated"}

@app.post("/api/auth/logout")
async def auth_logout(request: Request, user: dict = Depends(get_current_user)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    log_audit_event(
        user_callsign=user.get("callsign", "OPERATOR"),
        role=user.get("role", "OPERATOR"),
        action="USER_LOGOUT",
        resource="C2 Command Platform",
        details={"username": user.get("username")},
        ip_address=client_ip,
    )
    return {"status": "logged_out", "message": "Tactical session terminated."}

@app.get("/api/auth/me")
async def auth_me(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)):
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="No active session token. Authentication required.")
    user = verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid token. Please log in.")
    return {"status": "authenticated", "user": user}

@app.post("/api/auth/register")
async def auth_register(payload: RegisterRequest, request: Request, user: dict = Depends(require_role(["COMMANDER"]))):
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        from security.auth import register_user
        new_u = register_user(
            username=payload.username,
            password=payload.password,
            callsign=payload.callsign,
            role=payload.role,
            clearance=payload.clearance,
            station=payload.station,
        )
        log_audit_event(
            user_callsign=user.get("callsign", "COMMANDER"),
            role=user.get("role", "COMMANDER"),
            action="USER_REGISTER",
            resource=f"User: {payload.username}",
            details={"registered_username": payload.username, "role": payload.role},
            ip_address=client_ip,
        )
        return {"status": "created", "user": new_u}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/switch-role")
async def auth_switch_role(payload: SwitchRoleRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    role_map = {
        "COMMANDER": USERS_DB["commander"],
        "OPERATOR": USERS_DB["operator"],
        "ANALYST": USERS_DB["analyst"],
    }
    target = role_map.get(payload.role.upper())
    if not target:
        raise HTTPException(status_code=400, detail=f"Invalid role '{payload.role}'. Must be COMMANDER, OPERATOR, or ANALYST.")
    profile = dict(target)
    del profile["password"]
    token = create_access_token(profile)
    log_audit_event(
        user_callsign=profile["callsign"],
        role=profile["role"],
        action="ROLE_SWITCH",
        resource="Operator Terminal",
        details={"switched_to": profile["role"]},
        ip_address=client_ip,
    )
    return {"token": token, "user": profile}


# ── Compliance Audit Trail ───────────────────────────────────────────────────

@app.get("/api/audit-logs")
async def api_get_audit_logs(limit: int = 100, offset: int = 0, action: Optional[str] = None, role: Optional[str] = None):
    return get_audit_logs(limit=limit, offset=offset, action=action, role=role)


# ── Multi-Camera Network & Edge Telemetry ─────────────────────────────────────

@app.get("/api/cameras")
async def api_get_cameras():
    return {"cameras": camera_manager.get_cameras()}

@app.post("/api/cameras/switch")
async def api_switch_camera(payload: CameraSwitchPayload, user: dict = Depends(get_current_user)):
    res = camera_manager.switch_camera(payload.camera_id)
    if res.get("status") == "error":
        raise HTTPException(status_code=404, detail=res.get("message"))
    log_audit_event(
        user_callsign=user.get("callsign", "Commander"),
        role=user.get("role", "COMMANDER"),
        action="CAMERA_SWITCH",
        resource=f"Camera [{payload.camera_id}]",
        details=res,
    )
    return res

@app.get("/api/edge/telemetry")
async def api_edge_telemetry():
    return camera_manager.get_edge_telemetry()


# ═══════════════════════════════════════════════════════════════════════════════
# Serialisers
# ═══════════════════════════════════════════════════════════════════════════════

def _alert_to_dict(a: "Alert") -> dict:
    return {
        "id": a.id,
        "camera_id": a.camera_id,
        "alert_type": a.alert_type,
        "type": a.alert_type,
        "message": a.message,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "status": a.status,
        "risk_score": a.risk_score_value,
        "risk_score_value": a.risk_score_value,
        "contributing_factors": a.contributing_factors or [],
        "explainability": a.explainability or {},
        "operator_feedback": a.operator_feedback,
    }

def _event_to_dict(e: "Event") -> dict:
    return {
        "id": e.id,
        "camera_id": e.camera_id,
        "event_type": e.event_type,
        "track_id": e.track_id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "zone_id": e.zone_id,
        "details": e.details or {},
    }

def _risk_to_dict(r: "RiskScore") -> dict:
    return {
        "id": r.id,
        "camera_id": r.camera_id,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "score": r.score,
        "contributing_factors": r.contributing_factors or [],
        "event_ids": r.event_ids or [],
    }

def _zone_to_dict(z: "Zone") -> dict:
    return {
        "id": z.id,
        "camera_id": z.camera_id,
        "name": z.name,
        "polygon_points": z.polygon_points or [],
        "is_active": z.is_active,
        "created_at": z.created_at.isoformat() if z.created_at else None,
    }

def _baseline_to_dict(b: "BaselineStat") -> dict:
    return {
        "hour_bucket": b.hour_bucket,
        "day_type": b.day_type,
        "avg_person_count": b.avg_person_count,
        "avg_vehicle_count": b.avg_vehicle_count,
        "typical_dwell_time_seconds": b.typical_dwell_time_seconds,
        "typical_zone_entries_per_hour": b.typical_zone_entries_per_hour,
        "stddev_person_count": b.stddev_person_count,
        "stddev_vehicle_count": b.stddev_vehicle_count,
        "sample_count": b.sample_count,
        "dismissed_alert_count": b.dismissed_alert_count,
        "last_updated": b.last_updated.isoformat() if b.last_updated else None,
    }

def _evidence_to_dict(ev: "Evidence") -> dict:
    return {
        "id": ev.id,
        "event_id": ev.event_id,
        "alert_id": ev.alert_id,
        "camera_id": ev.camera_id,
        "snapshot_path": ev.snapshot_path,
        "clip_path": ev.clip_path,
        "thumbnail_path": ev.thumbnail_path,
        "sync_status": ev.sync_status,
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
    }


def run_server(host: str = "0.0.0.0", port: int = 8000):
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_server()