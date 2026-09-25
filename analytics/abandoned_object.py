"""
analytics/abandoned_object.py
Detects bags, suitcases and similar items left unattended (without a nearby person).
"""

import json
import logging
from datetime import datetime
from typing import Optional

from database.db import get_db
from database.models import Event

logger = logging.getLogger(__name__)

# Object classes treated as potential abandoned items
_ITEM_CLASSES: frozenset[str] = frozenset({"backpack", "suitcase", "handbag"})
# Object class for persons
_PERSON_CLASS: str = "person"
# Pixel distance threshold for "near a person"
_PROXIMITY_PIXELS: float = 100.0


class AbandonedObjectDetector:
    """
    Tracks bags / suitcases / handbags and fires an *abandoned_object* event
    when one has been unattended (no person within ``_PROXIMITY_PIXELS``) for
    longer than *absence_threshold_seconds*.

    Internal state per item track::

        {
            "last_near_person": datetime | None,   # most recent frame where a person was close
            "position": (x, y),                    # latest recorded position
            "class_name": str,                     # e.g. "suitcase"
            "alerted": bool,                       # True once an event is fired
        }

    Usage::

        detector = AbandonedObjectDetector(camera_id="cam_01",
                                           absence_threshold_seconds=60)
        events = detector.update(detections=[...], timestamp=datetime.utcnow())
    """

    def __init__(self, camera_id: str, absence_threshold_seconds: int = 60) -> None:
        """
        Parameters
        ----------
        camera_id:                  Camera identifier.
        absence_threshold_seconds:  How many seconds without a nearby person
                                    before the object is declared abandoned.
        """
        self.camera_id = camera_id
        self.absence_threshold_seconds = absence_threshold_seconds

        # item track_id -> state dict
        self._item_tracks: dict[int, dict] = {}

    # ------------------------------------------------------------------
    # Core update
    # ------------------------------------------------------------------

    def update(self, detections: list[dict], timestamp: datetime) -> list[dict]:
        """
        Process one frame's worth of detections.

        Parameters
        ----------
        detections: List of dicts with keys:
                      - ``track_id``  (int)
                      - ``class_name`` (str)
                      - ``position``  (x, y) tuple
        timestamp:  UTC datetime for this frame.

        Returns
        -------
        List of event dicts for any newly detected abandoned objects (usually
        empty; may contain multiple if several items become unattended at once).
        """
        # Partition detections by category
        person_positions: list[tuple] = []
        item_detections: list[dict] = []

        for det in detections:
            cls = det.get("class_name", "")
            pos = det.get("position", (0, 0))
            if cls == _PERSON_CLASS:
                person_positions.append(pos)
            elif cls in _ITEM_CLASSES:
                item_detections.append(det)

        # Update item tracks
        seen_item_ids: set[int] = set()
        for det in item_detections:
            tid = det["track_id"]
            pos = det["position"]
            seen_item_ids.add(tid)

            near_person = self._is_near_person(pos, person_positions)

            if tid not in self._item_tracks:
                self._item_tracks[tid] = {
                    "last_near_person": timestamp if near_person else None,
                    "position": pos,
                    "class_name": det.get("class_name", "object"),
                    "alerted": False,
                }
            else:
                state = self._item_tracks[tid]
                state["position"] = pos
                if near_person:
                    state["last_near_person"] = timestamp

        # Remove tracks not seen this frame
        lost = set(self._item_tracks.keys()) - seen_item_ids
        for tid in lost:
            del self._item_tracks[tid]

        # Check for abandoned items
        fired_events: list[dict] = []
        for tid, state in self._item_tracks.items():
            if state["alerted"]:
                continue

            last_near = state["last_near_person"]
            if last_near is None:
                # Item has never been near a person — use track start as reference
                # We cannot reliably compute absence without a first_seen; skip.
                continue

            absence_seconds = (timestamp - last_near).total_seconds()
            if absence_seconds >= self.absence_threshold_seconds:
                state["alerted"] = True
                event = self._write_event(
                    track_id=tid,
                    class_name=state["class_name"],
                    position=state["position"],
                    absence_seconds=absence_seconds,
                    timestamp=timestamp,
                )
                fired_events.append(event)

        return fired_events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_near_person(item_pos: tuple, person_positions: list[tuple]) -> bool:
        """Return True if *item_pos* is within ``_PROXIMITY_PIXELS`` of any person."""
        ix, iy = item_pos
        for px, py in person_positions:
            dist = ((ix - px) ** 2 + (iy - py) ** 2) ** 0.5
            if dist < _PROXIMITY_PIXELS:
                return True
        return False

    def _write_event(
        self,
        track_id: int,
        class_name: str,
        position: tuple,
        absence_seconds: float,
        timestamp: datetime,
    ) -> dict:
        """Persist an abandoned_object Event to the database and return its dict."""
        details = {
            "class_name": class_name,
            "position": list(position),
            "absence_seconds": round(absence_seconds, 2),
        }
        with get_db() as session:
            event = Event(
                camera_id=self.camera_id,
                event_type="abandoned_object",
                track_id=track_id,
                timestamp=timestamp,
                zone_id=None,
                details=json.dumps(details),
            )
            session.add(event)
            session.flush()
            result = event.to_dict()

        logger.warning(
            "ABANDONED OBJECT: camera=%s track=%d class=%s pos=%s absent=%.1fs",
            self.camera_id,
            track_id,
            class_name,
            position,
            absence_seconds,
        )
        return result
