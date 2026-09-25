"""
analytics/zone_manager.py
Manages restricted polygonal zones per camera and provides spatial containment tests.
"""

import json
import logging
from datetime import datetime
from typing import Optional

import cv2
import numpy as np

from database.db import get_db
from database.models import Zone

logger = logging.getLogger(__name__)


class ZoneManager:
    """
    CRUD interface for camera zones and fast point-in-polygon testing.

    Zones are stored as rows in the `zones` table.  The `polygon_points`
    column holds a JSON-encoded list of [x, y] pairs.
    """

    # ------------------------------------------------------------------
    # Public API — database operations
    # ------------------------------------------------------------------

    def get_zones(self, camera_id: str) -> list[dict]:
        """
        Return all active zones for *camera_id* as plain dicts.

        Each dict contains: id, name, polygon_points (list of [x, y]).
        """
        with get_db() as session:
            zones = (
                session.query(Zone)
                .filter(Zone.camera_id == camera_id, Zone.is_active == True)  # noqa: E712
                .all()
            )
            return [z.to_dict() for z in zones]

    def create_zone(self, camera_id: str, name: str, polygon_points: list) -> dict:
        """
        Insert a new Zone row into the database and return its dict representation.

        Parameters
        ----------
        camera_id:       Camera identifier string.
        name:            Human-readable zone label (e.g. "Perimeter North").
        polygon_points:  List of [x, y] pairs defining the polygon vertices.
        """
        with get_db() as session:
            zone = Zone(
                camera_id=camera_id,
                name=name,
                polygon_points=json.dumps(polygon_points),
                created_at=datetime.utcnow(),
                is_active=True,
            )
            session.add(zone)
            session.flush()  # populate zone.id before commit
            result = zone.to_dict()
            logger.info("Created zone '%s' (id=%d) for camera '%s'.", name, zone.id, camera_id)
        return result

    def delete_zone(self, zone_id: int) -> bool:
        """
        Soft-delete a zone by setting is_active=False.

        Returns True if the zone was found and deactivated, False otherwise.
        """
        with get_db() as session:
            zone = session.query(Zone).filter(Zone.id == zone_id).first()
            if zone is None:
                logger.warning("delete_zone: zone id=%d not found.", zone_id)
                return False
            zone.is_active = False
            logger.info("Deactivated zone id=%d ('%s').", zone_id, zone.name)
        return True

    # ------------------------------------------------------------------
    # Spatial helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_in_zone(point: tuple, polygon_points: list) -> bool:
        """
        Test whether *point* (x, y) lies inside or on the boundary of the
        polygon defined by *polygon_points*.

        Uses OpenCV's pointPolygonTest for sub-pixel accuracy.

        Parameters
        ----------
        point:           (x, y) float/int tuple.
        polygon_points:  List of [x, y] pairs (≥ 3 vertices required).

        Returns
        -------
        bool — True if the point is inside or on the boundary.
        """
        if len(polygon_points) < 3:
            return False
        contour = np.array(polygon_points, dtype=np.float32)
        result = cv2.pointPolygonTest(contour, (float(point[0]), float(point[1])), False)
        return result >= 0

    def get_zone_containing_point(self, point: tuple, zones: list) -> Optional[dict]:
        """
        Return the first zone dict from *zones* that contains *point*, or None.

        Parameters
        ----------
        point:  (x, y) tuple.
        zones:  List of zone dicts as returned by :meth:`get_zones`.
        """
        for zone in zones:
            if self.is_in_zone(point, zone.get("polygon_points", [])):
                return zone
        return None
