"""
baseline_engine/baseline_model.py
Behavioural baseline model using Welford's online algorithm.

This is Innovation 1 of the Border Surveillance System: instead of fixed
thresholds, the system learns what "normal" looks like for each camera at
each hour of the day and day-type (weekday/weekend), then flags statistical
anomalies relative to that learned baseline.
"""

import logging
import math
from datetime import datetime
from typing import Optional

from sqlalchemy.exc import IntegrityError

from database.db import get_db
from database.models import BaselineStat

logger = logging.getLogger(__name__)


class BaselineModel:
    """
    Per-camera behavioural baseline backed by the ``baseline_stats`` table.

    Workflow
    --------
    1. On first deployment call :meth:`seed_synthetic_baseline` so the demo
       immediately has plausible baselines.
    2. Each time a frame/minute observation is ready, call
       :meth:`update_baseline` to refine the model incrementally.
    3. :meth:`get_baseline` supplies the current model parameters to the
       anomaly scorer.

    Welford's online algorithm
    --------------------------
    For each new observation *x* given existing mean *m* and variance *M2*
    with *n* samples::

        n    += 1
        delta = x - m
        m    += delta / n
        delta2 = x - m
        M2   += delta * delta2
        stddev = sqrt(M2 / n)  # population stddev
    """

    def __init__(self, camera_id: str, bootstrap_days: int = 3) -> None:
        """
        Parameters
        ----------
        camera_id:       Camera identifier string.
        bootstrap_days:  Informational only — minimum days before the model is
                         considered meaningful (currently not enforced by a
                         strict cutoff; see :meth:`is_bootstrapped`).
        """
        self.camera_id = camera_id
        self.bootstrap_days = bootstrap_days

    # ------------------------------------------------------------------
    # Bootstrap / readiness
    # ------------------------------------------------------------------

    def is_bootstrapped(self) -> bool:
        """
        Return True if this camera has at least one baseline_stat row with
        ``sample_count > 10``, indicating the model has seen enough data to
        provide meaningful z-scores.
        """
        with get_db() as session:
            count = (
                session.query(BaselineStat)
                .filter(
                    BaselineStat.camera_id == self.camera_id,
                    BaselineStat.sample_count > 10,
                )
                .count()
            )
        return count > 0

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_baseline(self, hour: int, day_type: str) -> Optional[dict]:
        """
        Fetch the baseline row for ``(camera_id, hour, day_type)``.

        Parameters
        ----------
        hour:     Integer 0-23.
        day_type: ``'weekday'`` or ``'weekend'``.

        Returns
        -------
        Dict with all baseline_stat fields, or ``None`` if not found.
        """
        with get_db() as session:
            row = (
                session.query(BaselineStat)
                .filter(
                    BaselineStat.camera_id == self.camera_id,
                    BaselineStat.hour_bucket == hour,
                    BaselineStat.day_type == day_type,
                )
                .first()
            )
            return row.to_dict() if row else None

    def get_all_baselines(self) -> list[dict]:
        """Return all baseline rows for this camera ordered by day_type, hour."""
        with get_db() as session:
            rows = (
                session.query(BaselineStat)
                .filter(BaselineStat.camera_id == self.camera_id)
                .order_by(BaselineStat.day_type, BaselineStat.hour_bucket)
                .all()
            )
            return [r.to_dict() for r in rows]

    # ------------------------------------------------------------------
    # Update (Welford's online algorithm)
    # ------------------------------------------------------------------

    def update_baseline(self, hour: int, day_type: str, obs: dict) -> None:
        """
        Incorporate a new observation into the baseline using Welford's
        online algorithm (no need to store historical data).

        Parameters
        ----------
        hour:     Integer 0-23.
        day_type: ``'weekday'`` or ``'weekend'``.
        obs:      Dict with keys: person_count, vehicle_count,
                  dwell_time, zone_entries.
        """
        person_count = float(obs.get("person_count", 0))
        vehicle_count = float(obs.get("vehicle_count", 0))
        dwell_time = float(obs.get("dwell_time", 0))
        zone_entries = float(obs.get("zone_entries", 0))

        with get_db() as session:
            row = (
                session.query(BaselineStat)
                .filter(
                    BaselineStat.camera_id == self.camera_id,
                    BaselineStat.hour_bucket == hour,
                    BaselineStat.day_type == day_type,
                )
                .first()
            )

            if row is None:
                # Bootstrap with first observation
                row = BaselineStat(
                    camera_id=self.camera_id,
                    hour_bucket=hour,
                    day_type=day_type,
                    avg_person_count=person_count,
                    avg_vehicle_count=vehicle_count,
                    typical_dwell_time_seconds=dwell_time,
                    typical_zone_entries_per_hour=zone_entries,
                    stddev_person_count=0.0,
                    stddev_vehicle_count=0.0,
                    stddev_dwell_time=0.0,
                    stddev_zone_entries=0.0,
                    sample_count=1,
                    last_updated=datetime.utcnow(),
                )
                session.add(row)
            else:
                n = row.sample_count + 1

                def _welford_update(mean: float, stddev: float, n: int, x: float):
                    """
                    Returns updated (mean, stddev) using Welford's online algorithm.
                    stddev is population standard deviation: stddev = sqrt(M2 / n_prev).
                    We reconstruct old M2 consistently as stddev² * row.sample_count.
                    """
                    prev_n = max(row.sample_count, 1)
                    old_m2 = (stddev ** 2) * prev_n
                    delta = x - mean
                    new_mean = mean + delta / n
                    delta2 = x - new_mean
                    new_m2 = max(0.0, old_m2 + delta * delta2)
                    new_stddev = math.sqrt(new_m2 / n) if n > 0 else 0.0
                    return new_mean, new_stddev

                row.avg_person_count, row.stddev_person_count = _welford_update(
                    row.avg_person_count, row.stddev_person_count, n, person_count
                )
                row.avg_vehicle_count, row.stddev_vehicle_count = _welford_update(
                    row.avg_vehicle_count, row.stddev_vehicle_count, n, vehicle_count
                )
                row.typical_dwell_time_seconds, row.stddev_dwell_time = _welford_update(
                    row.typical_dwell_time_seconds, row.stddev_dwell_time, n, dwell_time
                )
                row.typical_zone_entries_per_hour, row.stddev_zone_entries = _welford_update(
                    row.typical_zone_entries_per_hour, row.stddev_zone_entries, n, zone_entries
                )
                row.sample_count = n
                row.last_updated = datetime.utcnow()

        logger.debug(
            "BaselineModel updated for camera=%s hour=%02d day_type=%s samples=%d",
            self.camera_id,
            hour,
            day_type,
            row.sample_count if row else 1,
        )

    # ------------------------------------------------------------------
    # Synthetic baseline seeding
    # ------------------------------------------------------------------

    def seed_synthetic_baseline(self) -> None:
        """
        Pre-populate baseline_stats with realistic synthetic data for all
        24 hours × 2 day_types so the anomaly scorer works immediately on
        first demo run.

        Activity profile
        ----------------
        * **Night  (00-05):** Very low activity — border is quieter.
        * **Off-peak (06-08, 18-23):** Medium activity — shift changes, patrols.
        * **Peak  (09-17):** Higher activity — main daylight operational hours.

        stddev is set to 30% of the mean so that moderate deviations
        (< 1σ) are normal while large deviations surface as anomalies.
        sample_count is set to 50 to pass the :meth:`is_bootstrapped` check.
        """
        _NIGHT = range(0, 6)       # 00-05
        _OFF_A = range(6, 9)       # 06-08
        _PEAK = range(9, 18)       # 09-17
        _OFF_B = range(18, 24)     # 18-23

        def _profile(hour: int) -> dict:
            if hour in _NIGHT:
                return dict(person=1.0, vehicle=0.2, dwell=15.0, entries=0.5)
            elif hour in _OFF_A or hour in _OFF_B:
                return dict(person=4.0, vehicle=1.5, dwell=45.0, entries=3.0)
            else:  # PEAK
                return dict(person=8.0, vehicle=3.0, dwell=90.0, entries=8.0)

        with get_db() as session:
            for day_type in ("weekday", "weekend"):
                for hour in range(24):
                    # Check existing row
                    existing = (
                        session.query(BaselineStat)
                        .filter(
                            BaselineStat.camera_id == self.camera_id,
                            BaselineStat.hour_bucket == hour,
                            BaselineStat.day_type == day_type,
                        )
                        .first()
                    )
                    if existing is not None:
                        logger.debug(
                            "Skipping seed for camera=%s hour=%d day=%s (already exists).",
                            self.camera_id, hour, day_type,
                        )
                        continue

                    p = _profile(hour)
                    # Weekend is slightly busier for persons, fewer vehicles
                    if day_type == "weekend":
                        p["person"] *= 1.2
                        p["vehicle"] *= 0.7

                    row = BaselineStat(
                        camera_id=self.camera_id,
                        hour_bucket=hour,
                        day_type=day_type,
                        avg_person_count=p["person"],
                        avg_vehicle_count=p["vehicle"],
                        typical_dwell_time_seconds=p["dwell"],
                        typical_zone_entries_per_hour=p["entries"],
                        stddev_person_count=max(p["person"] * 0.3, 0.1),
                        stddev_vehicle_count=max(p["vehicle"] * 0.3, 0.1),
                        stddev_dwell_time=max(p["dwell"] * 0.3, 1.0),
                        stddev_zone_entries=max(p["entries"] * 0.3, 0.1),
                        sample_count=50,
                        dismissed_alert_count=0,
                        last_updated=datetime.utcnow(),
                    )
                    session.add(row)

        logger.info(
            "BaselineModel: seeded synthetic baseline for camera='%s' (48 rows).",
            self.camera_id,
        )
