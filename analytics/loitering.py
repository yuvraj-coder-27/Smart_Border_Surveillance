"""
analytics/loitering.py
Detects objects that remain stationary within a confined area for too long.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from database.db import get_db
from database.models import Event

logger = logging.getLogger(__name__)


class LoiteringDetector:
    """
    Fires a *loitering* event when a tracked object:

    1. Has been visible for longer than *dwell_threshold_seconds*, AND
    2. All of its recorded positions span an area smaller than
       *area_threshold_ratio* × frame area (i.e. it is staying put), AND
    3. A loitering event has not already been fired for this track.

    The bounding area of recorded positions is calculated as
    ``(max_x - min_x) × (max_y - min_y)``.

    Usage::

        detector = LoiteringDetector(camera_id="cam_01", dwell_threshold_seconds=30)
        event = detector.update(track_id=7, position=(310, 240),
                                frame_size=(640, 480),
                                timestamp=datetime.utcnow())
        if event:
            print("Loitering detected!", event)
    """

    def __init__(
        self,
        camera_id: str,
        dwell_threshold_seconds: int = 30,
        area_threshold_ratio: float = 0.2,
    ) -> None:
        """
        Parameters
        ----------
        camera_id:               Camera this detector is attached to.
        dwell_threshold_seconds: Minimum duration (s) before loitering fires.
        area_threshold_ratio:    Maximum fraction of frame area the object may
                                 wander before loitering is *not* flagged.
        """
        self.camera_id = camera_id
        self.dwell_threshold_seconds = dwell_threshold_seconds
        self.area_threshold_ratio = area_threshold_ratio

        # track_id -> {first_seen: datetime, positions: list[tuple], alerted: bool}
        self._tracks: dict[int, dict] = {}

    # ------------------------------------------------------------------
    # Core update
    # ------------------------------------------------------------------

    def update(
        self,
        track_id: int,
        position: tuple,
        frame_size: tuple,
        timestamp: datetime,
    ) -> Optional[dict]:
        """
        Record *position* for *track_id* and test for loitering.

        Parameters
        ----------
        track_id:   Tracker-assigned integer ID.
        position:   Current (x, y) pixel coordinates.
        frame_size: (width, height) of the source frame in pixels.
        timestamp:  UTC datetime of this observation.

        Returns
        -------
        Event dict if a new loitering event was just written, else None.
        """
        if track_id not in self._tracks:
            self._tracks[track_id] = {
                "first_seen": timestamp,
                "positions": [position],
                "alerted": False,
            }
            return None

        track = self._tracks[track_id]
        track["positions"].append(position)

        # Already alerted — nothing more to do
        if track["alerted"]:
            return None

        # Check duration
        duration_seconds = (timestamp - track["first_seen"]).total_seconds()
        if duration_seconds <= self.dwell_threshold_seconds:
            return None

        # Check spatial spread
        frame_w, frame_h = frame_size
        frame_area = frame_w * frame_h
        if frame_area == 0:
            return None

        positions = track["positions"]
        xs = [p[0] for p in positions]
        ys = [p[1] for p in positions]
        bounding_area = (max(xs) - min(xs)) * (max(ys) - min(ys))
        area_ratio = bounding_area / frame_area

        if area_ratio >= self.area_threshold_ratio:
            # Object is moving around too much — not loitering
            return None

        # Fire loitering event
        track["alerted"] = True
        return self._write_event(track_id, duration_seconds, area_ratio, timestamp)

    # ------------------------------------------------------------------
    # Track lifecycle
    # ------------------------------------------------------------------

    def remove_track(self, track_id: int) -> None:
        """Remove *track_id* state when the tracker loses the object."""
        self._tracks.pop(track_id, None)
        logger.debug("LoiteringDetector: removed track %d.", track_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_event(
        self,
        track_id: int,
        duration_seconds: float,
        area_ratio: float,
        timestamp: datetime,
    ) -> dict:
        """Persist a loitering Event to the database and return its dict."""
        details = {
            "duration_seconds": round(duration_seconds, 2),
            "area_ratio": round(area_ratio, 4),
        }
        with get_db() as session:
            event = Event(
                camera_id=self.camera_id,
                event_type="loitering",
                track_id=track_id,
                timestamp=timestamp,
                zone_id=None,
                details=json.dumps(details),
            )
            session.add(event)
            session.flush()
            result = event.to_dict()

        logger.warning(
            "LOITERING: camera=%s track=%d duration=%.1fs area_ratio=%.3f",
            self.camera_id,
            track_id,
            duration_seconds,
            area_ratio,
        )
        return result
