"""
sync_layer/evidence_queue.py
─────────────────────────────
Evidence queue for the bandwidth-aware sync layer — Phase 7 (Innovation 2).

Strategy
--------
1. When new evidence arrives, write an ``Evidence`` row to the local DB with
   ``sync_status='metadata_only'`` and immediately push a lightweight metadata
   payload via :class:`MetadataSync`.
2. A background daemon thread periodically checks for Evidence rows that have a
   ``clip_path`` but are still ``metadata_only``.  It uploads the clip to the
   command centre and, on success, marks the row ``full_synced``.

This two-phase approach ensures that command-centre operators receive
actionable alerts within seconds even over a 2G / satellite link, while full
video evidence is uploaded opportunistically when bandwidth permits.
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime
from typing import Any

import requests

from config import settings
from database.db import get_db
from database.models import Evidence
from sync_layer.metadata_sync import MetadataSync

logger = logging.getLogger(__name__)


class EvidenceQueue:
    """
    Two-phase evidence uploader.

    Phase 1 — metadata only
        On :meth:`enqueue_evidence` a lightweight JSON payload is sent via
        :class:`MetadataSync` and the local DB record is created with
        ``sync_status='metadata_only'``.

    Phase 2 — full sync
        A background daemon thread wakes every
        ``settings.SYNC_CHECK_INTERVAL_SECONDS`` seconds, finds
        ``metadata_only`` rows that already have a ``clip_path``, uploads the
        clip file, and marks them ``full_synced``.

    Parameters
    ----------
    metadata_sync : MetadataSync
        Shared :class:`MetadataSync` instance used for phase-1 uploads.
    """

    # Endpoint for full clip upload.
    _CLIP_UPLOAD_PATH = "/api/ingest/clip"

    def __init__(self, metadata_sync: MetadataSync) -> None:
        self._metadata_sync: MetadataSync = metadata_sync
        self._background_thread: threading.Thread | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def enqueue_evidence(
        self,
        alert_id: int,
        event_id: int | None,
        camera_id: str,
        snapshot_path: str | None,
        clip_path: str | None,
        thumbnail_path: str | None,
        event_type: str,
        risk_score: float,
        timestamp: datetime,
    ) -> int:
        """
        Persist an Evidence record and immediately push its metadata upstream.

        Parameters
        ----------
        alert_id       : ID of the parent Alert row.
        event_id       : ID of the parent Event row, or ``None``.
        camera_id      : Source camera identifier.
        snapshot_path  : Local path to a JPEG still, or ``None``.
        clip_path      : Local path to the video clip, or ``None``.
        thumbnail_path : Local path to a thumbnail JPEG, or ``None``.
        event_type     : Type string of the triggering event.
        risk_score     : Computed risk score (0–100).
        timestamp      : UTC datetime of the event.

        Returns
        -------
        int
            The ``id`` of the newly created :class:`Evidence` DB row.
        """
        # ── Phase 1a: persist Evidence row ────────────────────────────────────
        with get_db() as session:
            evidence = Evidence(
                event_id=event_id,
                alert_id=alert_id,
                camera_id=camera_id,
                snapshot_path=snapshot_path,
                clip_path=clip_path,
                thumbnail_path=thumbnail_path,
                sync_status="metadata_only",
                created_at=datetime.utcnow(),
            )
            session.add(evidence)
            session.flush()  # obtain the PK before commit
            evidence_id = evidence.id

        logger.info(
            "EvidenceQueue: created Evidence id=%d for alert_id=%d (sync=metadata_only)",
            evidence_id,
            alert_id,
        )

        # ── Phase 1b: push lightweight metadata upstream ──────────────────────
        try:
            self._metadata_sync.queue_event_metadata(
                alert_id=alert_id,
                camera_id=camera_id,
                event_type=event_type,
                risk_score=risk_score,
                thumbnail_path=thumbnail_path,
                timestamp=timestamp,
            )
        except Exception as exc:  # noqa: BLE001
            # Never let a metadata push failure disrupt the calling pipeline.
            logger.exception(
                "EvidenceQueue: metadata push failed for alert_id=%d: %s",
                alert_id,
                exc,
            )

        return evidence_id

    def start_background_sync(self) -> None:
        """
        Start the background daemon thread that performs phase-2 (full) syncs.

        Calling this method more than once is safe — the second and subsequent
        calls are no-ops if a thread is already running.
        """
        if self._background_thread is not None and self._background_thread.is_alive():
            logger.debug("EvidenceQueue: background sync thread already running")
            return

        self._background_thread = threading.Thread(
            target=self._sync_loop,
            name="evidence-sync-worker",
            daemon=True,
        )
        self._background_thread.start()
        logger.info(
            "EvidenceQueue: background sync thread started (interval=%ds)",
            settings.SYNC_CHECK_INTERVAL_SECONDS,
        )

    def get_sync_status_summary(self) -> dict[str, int]:
        """
        Return a snapshot of how many Evidence rows are in each sync state.

        Returns
        -------
        dict
            ``{metadata_only: int, full_synced: int, total: int}``
        """
        with get_db() as session:
            metadata_only_count: int = (
                session.query(Evidence)
                .filter(Evidence.sync_status == "metadata_only")
                .count()
            )
            full_synced_count: int = (
                session.query(Evidence)
                .filter(Evidence.sync_status == "full_synced")
                .count()
            )

        total = metadata_only_count + full_synced_count
        return {
            "metadata_only": metadata_only_count,
            "full_synced": full_synced_count,
            "total": total,
        }

    # ── Background worker ─────────────────────────────────────────────────────

    def _sync_loop(self) -> None:
        """
        Daemon loop: sleep → attempt phase-2 upgrades → repeat.

        Runs indefinitely as a daemon thread so it does not block process exit.
        """
        logger.debug("EvidenceQueue._sync_loop: started")
        while True:
            time.sleep(settings.SYNC_CHECK_INTERVAL_SECONDS)
            try:
                self._try_upgrade_evidence()
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "EvidenceQueue._sync_loop: unhandled error: %s", exc
                )

    def _try_upgrade_evidence(self) -> None:
        """
        Find ``metadata_only`` Evidence rows that have a clip and upload them.

        For each eligible row:
          1. POST the clip file to the command centre.
          2. On success, update ``sync_status`` to ``'full_synced'``.
          3. On failure, leave the row unchanged for the next iteration.
        """
        with get_db() as session:
            candidates: list[Evidence] = (
                session.query(Evidence)
                .filter(
                    Evidence.sync_status == "metadata_only",
                    Evidence.clip_path.isnot(None),
                )
                .all()
            )

        if not candidates:
            logger.debug("EvidenceQueue._try_upgrade_evidence: no eligible rows")
            return

        logger.info(
            "EvidenceQueue._try_upgrade_evidence: found %d clip(s) to upload",
            len(candidates),
        )

        upload_url = (
            f"{self._metadata_sync.command_url.rstrip('/')}{self._CLIP_UPLOAD_PATH}"
        )

        for ev in candidates:
            self._upload_clip(ev, upload_url)

    def _upload_clip(self, evidence: Evidence, upload_url: str) -> None:
        """
        Upload a single clip file and update the Evidence row on success.

        Parameters
        ----------
        evidence   : The Evidence ORM object (detached from session).
        upload_url : Full URL to POST the clip to.
        """
        import os  # local import — only needed here

        clip_path: str = evidence.clip_path  # guaranteed non-None by caller
        evidence_id: int = evidence.id

        if not os.path.isfile(clip_path):
            logger.warning(
                "EvidenceQueue: clip file not found for Evidence id=%d: %s",
                evidence_id,
                clip_path,
            )
            return

        try:
            with open(clip_path, "rb") as clip_fh:
                response = requests.post(
                    upload_url,
                    files={"clip": (os.path.basename(clip_path), clip_fh, "video/mp4")},
                    data={
                        "evidence_id": str(evidence_id),
                        "alert_id": str(evidence.alert_id or ""),
                        "camera_id": evidence.camera_id,
                    },
                    timeout=60,  # generous timeout for large clip files
                )
            response.raise_for_status()

            # ── Mark as full_synced ────────────────────────────────────────────
            with get_db() as session:
                db_evidence: Evidence | None = session.get(Evidence, evidence_id)
                if db_evidence is not None:
                    db_evidence.sync_status = "full_synced"
                    # session commits automatically via get_db() context manager

            logger.info(
                "EvidenceQueue: clip uploaded for Evidence id=%d → full_synced",
                evidence_id,
            )

        except requests.exceptions.Timeout:
            logger.warning(
                "EvidenceQueue: clip upload timed out for Evidence id=%d — will retry",
                evidence_id,
            )
        except requests.exceptions.ConnectionError as exc:
            logger.warning(
                "EvidenceQueue: connection error uploading Evidence id=%d: %s — will retry",
                evidence_id,
                exc,
            )
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response else "?"
            logger.error(
                "EvidenceQueue: HTTP %s uploading Evidence id=%d: %s",
                status,
                evidence_id,
                exc,
            )
        except OSError as exc:
            logger.error(
                "EvidenceQueue: OS error reading clip for Evidence id=%d: %s",
                evidence_id,
                exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "EvidenceQueue: unexpected error for Evidence id=%d: %s",
                evidence_id,
                exc,
            )
