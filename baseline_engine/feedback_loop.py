"""
baseline_engine/feedback_loop.py
Operator feedback integration: dismissals drive automatic recalibration of
the behavioural baseline to reduce false-alarm fatigue.

When operators repeatedly dismiss alerts for a given camera/hour/day_type,
the system widens the stddev (tolerance) for that slot so equivalent
observations no longer trigger anomaly flags.
"""

import logging
from datetime import datetime
from typing import Optional

from database.db import get_db
from database.models import BaselineStat

logger = logging.getLogger(__name__)

# Minimum number of dismissals before recalibration is applied
_DISMISS_THRESHOLD: int = 3
# How much to widen each stddev column per recalibration event
_STDDEV_INCREASE_FACTOR: float = 1.20  # +20 %


class FeedbackLoop:
    """
    Tracks operator alert dismissals and recalibrates the behavioural baseline
    to reduce false positives over time.

    Recalibration logic
    -------------------
    When ``dismissed_alert_count >= 3`` for any baseline_stat row, that row's
    stddev values are increased by 20 % (making the z-score thresholds looser)
    and the dismissed count is reset to zero.

    Usage::

        fb = FeedbackLoop(camera_id="cam_01")
        fb.record_dismissal(camera_id="cam_01", alert_timestamp=datetime.utcnow())
        n_recalibrated = fb.recalibrate(camera_id="cam_01")
    """

    def __init__(self, camera_id: str) -> None:
        """
        Parameters
        ----------
        camera_id: Camera identifier this feedback loop is associated with.
        """
        self.camera_id = camera_id

    # ------------------------------------------------------------------
    # Record dismissal
    # ------------------------------------------------------------------

    def record_dismissal(self, camera_id: str, alert_timestamp: datetime) -> None:
        """
        Increment the dismissed_alert_count for the baseline_stat row that
        corresponds to the *hour* and *day_type* of *alert_timestamp*.

        Parameters
        ----------
        camera_id:       Camera the dismissed alert belongs to.
        alert_timestamp: UTC datetime of the alert being dismissed.
        """
        hour_bucket = alert_timestamp.hour
        # Python weekday(): Monday=0 … Sunday=6
        day_type = "weekend" if alert_timestamp.weekday() >= 5 else "weekday"

        with get_db() as session:
            row = (
                session.query(BaselineStat)
                .filter(
                    BaselineStat.camera_id == camera_id,
                    BaselineStat.hour_bucket == hour_bucket,
                    BaselineStat.day_type == day_type,
                )
                .first()
            )

            if row is None:
                logger.warning(
                    "FeedbackLoop.record_dismissal: no baseline row found for "
                    "camera=%s hour=%d day_type=%s — dismissal not recorded.",
                    camera_id, hour_bucket, day_type,
                )
                return

            row.dismissed_alert_count = (row.dismissed_alert_count or 0) + 1
            logger.info(
                "Dismissal recorded for camera=%s hour=%02d day_type=%s "
                "(total dismissed=%d).",
                camera_id, hour_bucket, day_type, row.dismissed_alert_count,
            )

    # ------------------------------------------------------------------
    # Recalibrate
    # ------------------------------------------------------------------

    def recalibrate(self, camera_id: str) -> int:
        """
        Apply recalibration to all baseline rows with excessive dismissals.

        For each row where ``dismissed_alert_count >= _DISMISS_THRESHOLD``:
        * Each stddev column is multiplied by ``_STDDEV_INCREASE_FACTOR``.
        * ``dismissed_alert_count`` is reset to 0.

        Parameters
        ----------
        camera_id: Camera to recalibrate.

        Returns
        -------
        int — Number of rows that were recalibrated.
        """
        recalibrated = 0

        with get_db() as session:
            rows = (
                session.query(BaselineStat)
                .filter(
                    BaselineStat.camera_id == camera_id,
                    BaselineStat.dismissed_alert_count >= _DISMISS_THRESHOLD,
                )
                .all()
            )

            for row in rows:
                row.stddev_person_count = (row.stddev_person_count or 0.1) * _STDDEV_INCREASE_FACTOR
                row.stddev_vehicle_count = (row.stddev_vehicle_count or 0.1) * _STDDEV_INCREASE_FACTOR
                row.stddev_dwell_time = (row.stddev_dwell_time or 1.0) * _STDDEV_INCREASE_FACTOR
                row.stddev_zone_entries = (row.stddev_zone_entries or 0.1) * _STDDEV_INCREASE_FACTOR
                row.dismissed_alert_count = 0
                row.last_updated = datetime.utcnow()
                recalibrated += 1

                logger.info(
                    "Recalibrated baseline for camera=%s hour=%02d day_type=%s "
                    "(stddev widened by %.0f%%).",
                    camera_id,
                    row.hour_bucket,
                    row.day_type,
                    (_STDDEV_INCREASE_FACTOR - 1.0) * 100,
                )

        return recalibrated

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_recalibration_summary(self, camera_id: str) -> dict:
        """
        Return a summary of current dismissal state for *camera_id*.

        Returns
        -------
        Dict with:

        * ``total_dismissed``         — sum of dismissed_alert_count across all rows
        * ``rows_needing_recalibration`` — rows where dismissed_alert_count >= threshold
        * ``last_recalibrated``       — ISO datetime string of the most recently
                                        updated row, or ``None``
        """
        with get_db() as session:
            rows = (
                session.query(BaselineStat)
                .filter(BaselineStat.camera_id == camera_id)
                .all()
            )

            if not rows:
                return {
                    "total_dismissed": 0,
                    "rows_needing_recalibration": 0,
                    "last_recalibrated": None,
                }

            total_dismissed = sum(r.dismissed_alert_count or 0 for r in rows)
            rows_needing = sum(
                1 for r in rows
                if (r.dismissed_alert_count or 0) >= _DISMISS_THRESHOLD
            )

            # Most recent last_updated among rows that have been updated
            last_updated_times = [r.last_updated for r in rows if r.last_updated is not None]
            last_recalibrated: Optional[str] = (
                max(last_updated_times).isoformat() if last_updated_times else None
            )

        return {
            "total_dismissed": total_dismissed,
            "rows_needing_recalibration": rows_needing,
            "last_recalibrated": last_recalibrated,
        }
