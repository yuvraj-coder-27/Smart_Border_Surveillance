"""
analytics/intrusion.py
Detects when tracked objects enter restricted zones and fires intrusion events.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from database.db import get_db
from database.models import Event
from analytics.zone_manager import ZoneManager

logger = logging.getLogger(__name__)


class IntrusionDetector:
    """
    Stateful detector that fires a single *intrusion* event the first time a
    tracked object enters a restricted zone.  Repeated detections of the same
    (track_id, zone) pair are suppressed until the track leaves the zone.

    Usage::

        detector = IntrusionDetector(camera_id="cam_01", zone_manager=zm)
        event = detector.check(track_id=42, bottom_center=(320, 480),
                               zones=zm.get_zones("cam_01"),
                               timestamp=datetime.utcnow())
        if event:
            print("Intrusion detected!", event)
    """

    def __init__(self, camera_id: str, zone_manager: ZoneManager) -> None:
        """
        Parameters
        ----------
        camera_id:    Identifier of the camera this detector belongs to.
        zone_manager: Shared :class:`ZoneManager` instance for spatial tests.
        """
        self.camera_id = camera_id
        self.zone_manager = zone_manager
        # Keys: (track_id, zone_id) — present when the track is inside a zone
        self._flagged: set[tuple[int, int]] = set()

    # ------------------------------------------------------------------
    # Core detection
    # ------------------------------------------------------------------

    def check(
        self,
        track_id: int,
        bottom_center: tuple,
        zones: list,
        timestamp: datetime,
        persist: bool = False,
        bbox: Optional[tuple | list] = None,
    ) -> Optional[dict]:
        """
        Check whether *bottom_center* (x, y) is inside any restricted zone.

        Behaviour:
        * If the point is inside a zone AND this (track_id, zone_id) pair has
          **not** been flagged before -> return an intrusion event dict.
        * If persist is True -> writes an Event to the DB immediately.
        * If persist is False -> returns in-memory dict suitable for queueing in the video pipeline.
        * If the track was previously flagged for a zone it is no longer in ->
          remove the flag (allows re-detection if it re-enters later).
        * Returns None when no new intrusion is detected.

        Parameters
        ----------
        track_id:      Unique tracker-assigned integer ID.
        bottom_center: (x, y) pixel coordinates of the object's foot-point.
        zones:         List of active zone dicts (from ZoneManager.get_zones).
        timestamp:     UTC datetime for the event record.
        persist:       Whether to synchronously insert an Event row into the DB.
        bbox:          Optional [x1, y1, x2, y2] bounding box of the intruder.
        """
        # Determine which zones currently contain this point
        current_zone_ids: set[int] = set()
        for zone in zones:
            if self.zone_manager.is_in_zone(bottom_center, zone.get("polygon_points", [])):
                current_zone_ids.add(zone["id"])

        # Remove flags for zones the track has left
        departed = {
            (tid, zid) for (tid, zid) in self._flagged
            if tid == track_id and zid not in current_zone_ids
        }
        self._flagged -= departed

        # Fire an event for each newly entered zone
        for zone in zones:
            zone_id = zone["id"]
            key = (track_id, zone_id)
            if zone_id in current_zone_ids and key not in self._flagged:
                self._flagged.add(key)
                if persist:
                    event_dict = self._write_event(track_id, zone, bottom_center, timestamp)
                    event_dict["type"] = "intrusion"
                    event_dict["message"] = f"Intrusion detected in zone '{zone['name']}' by Track #{track_id}"
                    event_dict["bbox"] = list(bbox) if bbox is not None else None
                    event_dict["confidence"] = 0.95
                    event_dict["critical"] = True
                    return event_dict
                else:
                    event_dict = {
                        "type": "intrusion",
                        "event_type": "intrusion",
                        "camera_id": self.camera_id,
                        "track_id": track_id,
                        "zone_id": zone_id,
                        "zone_name": zone.get("name", f"Zone #{zone_id}"),
                        "position": list(bottom_center),
                        "bbox": list(bbox) if bbox is not None else None,
                        "message": f"Intrusion detected in zone '{zone.get('name', zone_id)}' by Track #{track_id}",
                        "confidence": 0.95,
                        "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
                        "critical": True,
                    }
                    logger.warning(
                        "INTRUSION: camera=%s track=%d zone='%s' pos=%s",
                        self.camera_id,
                        track_id,
                        zone.get("name", zone_id),
                        bottom_center,
                    )
                    return event_dict

        return None

    # ------------------------------------------------------------------
    # Track lifecycle
    # ------------------------------------------------------------------

    def reset_track(self, track_id: int) -> None:
        """
        Remove all flagged zone entries for *track_id* (call when a track is
        lost or a new track with the same ID begins).
        """
        to_remove = {(tid, zid) for (tid, zid) in self._flagged if tid == track_id}
        self._flagged -= to_remove
        if to_remove:
            logger.debug("IntrusionDetector: cleared %d flag(s) for track %d.", len(to_remove), track_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_event(
        self,
        track_id: int,
        zone: dict,
        position: tuple,
        timestamp: datetime,
    ) -> dict:
        """Persist an intrusion Event to the database and return its dict."""
        details = {
            "zone_name": zone["name"],
            "position": list(position),
        }
        with get_db() as session:
            event = Event(
                camera_id=self.camera_id,
                event_type="intrusion",
                track_id=track_id,
                timestamp=timestamp,
                zone_id=zone["id"],
                details=json.dumps(details),
            )
            session.add(event)
            session.flush()
            result = event.to_dict()

        logger.warning(
            "INTRUSION: camera=%s track=%d zone='%s' pos=%s",
            self.camera_id,
            track_id,
            zone["name"],
            position,
        )
        return result
