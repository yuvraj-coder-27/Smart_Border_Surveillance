"""
sync_layer/metadata_sync.py
────────────────────────────
Bandwidth-Aware Metadata Sync — Phase 7 (Innovation 2).

Sends lightweight metadata payloads to the remote command centre whenever
connectivity is available, queuing them in memory when the link is down.

Class
-----
MetadataSync
    Thread-safe, in-memory queue that transmits event metadata to a remote
    endpoint and gracefully degrades when connectivity is poor.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any

import requests

from config import settings

logger = logging.getLogger(__name__)


class MetadataSync:
    """
    Lightweight metadata transmitter for the bandwidth-aware sync layer.

    Payloads are small JSON objects (no media) containing the alert ID,
    camera, event type, risk score, an optional thumbnail path, and a
    timestamp.  They are queued in memory and flushed on every ``queue_event_metadata``
    call and on every background sync attempt.

    Parameters
    ----------
    command_url : str, optional
        Base URL of the command centre API.  Defaults to
        ``settings.SYNC_COMMAND_URL``.

    Thread Safety
    -------------
    All mutations to ``self.sync_queue`` are protected by ``self._lock``.
    """

    # Endpoint paths
    _METADATA_PATH = "/api/ingest/metadata"
    _HEALTH_PATH = "/api/health"

    def __init__(self, command_url: str | None = None) -> None:
        self.command_url: str = (command_url or settings.SYNC_COMMAND_URL).rstrip("/")
        self.sync_queue: list[dict[str, Any]] = []
        self._lock: threading.Lock = threading.Lock()
        self._simulate_poor: bool = False

    # ── Public API ────────────────────────────────────────────────────────────

    def queue_event_metadata(
        self,
        alert_id: int,
        camera_id: str,
        event_type: str,
        risk_score: float,
        thumbnail_path: str | None,
        timestamp: datetime,
    ) -> None:
        """
        Build a lightweight metadata payload and enqueue it for transmission.

        The payload is intentionally small — no image / video bytes — so it
        can be transmitted even over a 2G / satellite link.

        Parameters
        ----------
        alert_id       : ID of the Alert record in the local DB.
        camera_id      : Identifier of the source camera.
        event_type     : Type of the triggering event (e.g. 'intrusion').
        risk_score     : Numeric risk score (0–100).
        thumbnail_path : Local path to the thumbnail file, or ``None``.
        timestamp      : UTC datetime of the event.
        """
        payload: dict[str, Any] = {
            "alert_id": alert_id,
            "camera_id": camera_id,
            "event_type": event_type,
            "risk_score": risk_score,
            "thumbnail_path": thumbnail_path,
            "timestamp_iso": timestamp.isoformat(),
            "payload_type": "metadata",
        }

        with self._lock:
            self.sync_queue.append(payload)
            logger.debug(
                "MetadataSync: queued metadata for alert_id=%d (queue depth=%d)",
                alert_id,
                len(self.sync_queue),
            )

        # Fire-and-forget attempt to drain the queue immediately.
        self._try_transmit()

    def get_queue_depth(self) -> int:
        """Return the number of metadata payloads currently awaiting transmission."""
        with self._lock:
            return len(self.sync_queue)

    def simulate_poor_connectivity(self, enabled: bool) -> None:
        """
        Toggle simulated poor connectivity for demo / testing purposes.

        When *enabled* is ``True``, :meth:`_check_connectivity` always
        returns ``False``, causing all payloads to stay queued.

        Parameters
        ----------
        enabled : bool
            ``True`` to simulate an offline link; ``False`` to restore
            normal connectivity checks.
        """
        self._simulate_poor = enabled
        logger.info(
            "MetadataSync: poor-connectivity simulation %s",
            "ENABLED" if enabled else "DISABLED",
        )
        if not enabled:
            # Connectivity restored — recover any records that arrived during outage
            self.recover_from_db()
            self._try_transmit()

    def recover_from_db(self) -> int:
        """
        Recover un-synced evidence metadata from local DB upon system reboot or reconnect.
        Ensures store-and-forward persistence across unexpected crashes or reboots.
        """
        recovered_count = 0
        try:
            from database.db import get_db
            from database.models import Evidence, Alert
            with get_db() as session:
                uncommitted = (
                    session.query(Evidence, Alert)
                    .join(Alert, Evidence.alert_id == Alert.id)
                    .filter(Evidence.sync_status.in_(["metadata_only", "pending"]))
                    .all()
                )
                with self._lock:
                    existing_alert_ids = {p.get("alert_id") for p in self.sync_queue}
                    for ev, al in uncommitted:
                        if al.id not in existing_alert_ids:
                            self.sync_queue.append({
                                "alert_id": al.id,
                                "camera_id": al.camera_id,
                                "event_type": al.alert_type,
                                "risk_score": al.risk_score_value or 0.0,
                                "thumbnail_path": ev.thumbnail_path or ev.snapshot_path,
                                "timestamp_iso": al.timestamp.isoformat() if al.timestamp else datetime.utcnow().isoformat(),
                                "payload_type": "metadata",
                            })
                            recovered_count += 1
            if recovered_count > 0:
                logger.info(f"MetadataSync: recovered {recovered_count} unsynced alert metadata records from database")
        except Exception as e:
            logger.warning(f"MetadataSync: DB recovery error: {e}")
        return recovered_count


    # ── Internal helpers ──────────────────────────────────────────────────────

    def _try_transmit(self) -> bool:
        """
        Attempt to transmit all queued payloads to the command centre.

        Each item is POSTed individually.  Successfully transmitted items are
        removed from the queue; failed items remain so they can be retried.

        Returns
        -------
        bool
            ``True`` if at least one item was successfully transmitted.
        """
        if not self._check_connectivity():
            logger.debug(
                "MetadataSync: no connectivity — %d item(s) remain queued",
                self.get_queue_depth(),
            )
            return False

        url = f"{self.command_url}{self._METADATA_PATH}"
        transmitted_any = False

        with self._lock:
            # Iterate over a snapshot; we'll rebuild the list from failures.
            pending = list(self.sync_queue)
            still_pending: list[dict[str, Any]] = []

            for item in pending:
                try:
                    response = requests.post(url, json=item, timeout=5)
                    response.raise_for_status()
                    transmitted_any = True
                    logger.info(
                        "MetadataSync: transmitted alert_id=%s to %s",
                        item.get("alert_id"),
                        url,
                    )
                    try:
                        from database.db import get_db
                        from database.models import Evidence
                        with get_db() as session:
                            ev = session.query(Evidence).filter(Evidence.alert_id == item.get("alert_id")).first()
                            if ev and ev.sync_status in ["metadata_only", "pending"]:
                                ev.sync_status = "metadata_synced"
                                session.commit()
                    except Exception:
                        pass

                except requests.exceptions.Timeout:
                    logger.warning(
                        "MetadataSync: POST timed out for alert_id=%s — will retry",
                        item.get("alert_id"),
                    )
                    still_pending.append(item)
                except requests.exceptions.ConnectionError as exc:
                    logger.warning(
                        "MetadataSync: connection error for alert_id=%s: %s — will retry",
                        item.get("alert_id"),
                        exc,
                    )
                    still_pending.append(item)
                except requests.exceptions.HTTPError as exc:
                    # 4xx errors are not retriable (bad payload); drop the item.
                    status = exc.response.status_code if exc.response else "?"
                    if status and 400 <= int(status) < 500:
                        logger.error(
                            "MetadataSync: server rejected alert_id=%s (HTTP %s) — dropping",
                            item.get("alert_id"),
                            status,
                        )
                    else:
                        logger.warning(
                            "MetadataSync: server error for alert_id=%s (HTTP %s) — will retry",
                            item.get("alert_id"),
                            status,
                        )
                        still_pending.append(item)
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "MetadataSync: unexpected error for alert_id=%s: %s — will retry",
                        item.get("alert_id"),
                        exc,
                    )
                    still_pending.append(item)

            self.sync_queue = still_pending

        return transmitted_any

    def _check_connectivity(self) -> bool:
        """
        Probe the command centre health endpoint.

        Returns
        -------
        bool
            ``True`` if the remote server responds with HTTP 200;
            ``False`` on any network error or non-200 status.
        """
        if self._simulate_poor:
            logger.debug("MetadataSync: connectivity check suppressed (simulation mode)")
            return False

        url = f"{self.command_url}{self._HEALTH_PATH}"
        try:
            response = requests.get(url, timeout=2)
            return response.status_code == 200
        except Exception:  # noqa: BLE001
            return False
