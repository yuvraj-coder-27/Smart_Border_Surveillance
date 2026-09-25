"""
baseline_engine/anomaly_scoring.py
Z-score-based anomaly scorer that compares live observations against the
learned behavioural baseline.
"""

import logging
from typing import Optional

from baseline_engine.baseline_model import BaselineModel

logger = logging.getLogger(__name__)

# Z-score magnitude above which a feature is considered anomalous
_Z_FLAG_THRESHOLD: float = 1.5
# Hard clamp on z-scores to prevent extreme outliers from dominating
_Z_CLAMP: float = 5.0
# Minimum stddev used in denominator to avoid division-by-zero
_MIN_STDDEV: float = 0.1
# Score per unit of summed clamped |z|
_SCORE_PER_Z_UNIT: float = 10.0


class AnomalyScorer:
    """
    Computes a 0-100 anomaly score by comparing live observations against the
    behavioural baseline for the current hour and day-type.

    If the baseline is not yet bootstrapped (insufficient samples), the scorer
    returns a zero score and flags the system as still in the bootstrap period.

    Score formula
    -------------
    ::

        for each feature f in {person_count, vehicle_count, dwell_time, zone_entries}:
            z_f = (obs_f - mean_f) / max(stddev_f, MIN_STDDEV)
            z_f = clamp(z_f, -Z_CLAMP, +Z_CLAMP)

        baseline_score = min(100, max(0, sum(|z_f|) * SCORE_PER_Z_UNIT))

    Usage::

        scorer = AnomalyScorer(camera_id="cam_01", baseline_model=model)
        result = scorer.score(observations={...}, events=[...],
                              hour=14, day_type="weekday")
    """

    def __init__(self, camera_id: str, baseline_model: BaselineModel) -> None:
        """
        Parameters
        ----------
        camera_id:      Camera identifier.
        baseline_model: Pre-constructed :class:`BaselineModel` for the same camera.
        """
        self.camera_id = camera_id
        self.baseline_model = baseline_model

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    def score(
        self,
        observations: dict,
        events: list[dict],
        hour: int,
        day_type: str,
    ) -> dict:
        """
        Compute an anomaly score for the given observations and events.

        Parameters
        ----------
        observations: Dict with keys:
                        - ``person_count``  (int/float)
                        - ``vehicle_count`` (int/float)
                        - ``dwell_time``    (float, seconds)
                        - ``zone_entries``  (int/float)
        events:       List of recent event dicts; each contributes a factor string.
        hour:         Current UTC hour (0-23).
        day_type:     ``'weekday'`` or ``'weekend'``.

        Returns
        -------
        Dict with keys:

        * ``score``              — float 0-100
        * ``factors``            — list[str] of human-readable contributing factors
        * ``z_scores``           — {person, vehicle, dwell, zone_entries} (only if active)
        * ``is_baseline_active`` — bool
        """
        # --- Bootstrap check ---
        if not self.baseline_model.is_bootstrapped():
            return {
                "score": 0.0,
                "factors": [
                    "System in bootstrap period — using rule-based scoring only"
                ],
                "is_baseline_active": False,
            }

        # --- Fetch baseline ---
        baseline = self.baseline_model.get_baseline(hour, day_type)
        if baseline is None:
            return {
                "score": 0.0,
                "factors": [
                    f"No baseline data found for hour={hour} day_type={day_type}"
                ],
                "is_baseline_active": False,
            }

        # --- Extract observed values ---
        obs_person = float(observations.get("person_count", 0))
        obs_vehicle = float(observations.get("vehicle_count", 0))
        obs_dwell = float(observations.get("dwell_time", 0))
        obs_entries = float(observations.get("zone_entries", 0))

        # --- Compute z-scores ---
        def _z(obs: float, mean: float, stddev: float) -> float:
            z = (obs - mean) / max(stddev, _MIN_STDDEV)
            return max(-_Z_CLAMP, min(_Z_CLAMP, z))

        z_person = _z(obs_person,
                      baseline["avg_person_count"],
                      baseline["stddev_person_count"])
        z_vehicle = _z(obs_vehicle,
                       baseline["avg_vehicle_count"],
                       baseline["stddev_vehicle_count"])
        z_dwell = _z(obs_dwell,
                     baseline["typical_dwell_time_seconds"],
                     baseline["stddev_dwell_time"])
        z_entries = _z(obs_entries,
                       baseline["typical_zone_entries_per_hour"],
                       baseline["stddev_zone_entries"])

        z_scores = {
            "person": round(z_person, 3),
            "vehicle": round(z_vehicle, 3),
            "dwell": round(z_dwell, 3),
            "zone_entries": round(z_entries, 3),
        }

        # --- Build contributing factors ---
        factors: list[str] = []

        if abs(z_person) > _Z_FLAG_THRESHOLD:
            direction = "above" if z_person > 0 else "below"
            factors.append(
                f"Person count {obs_person:.0f} is {abs(z_person):.1f}σ {direction} "
                f"baseline for {hour:02d}:00"
            )

        if abs(z_vehicle) > _Z_FLAG_THRESHOLD:
            direction = "above" if z_vehicle > 0 else "below"
            factors.append(
                f"Vehicle count {obs_vehicle:.0f} is {abs(z_vehicle):.1f}σ {direction} "
                f"baseline for {hour:02d}:00"
            )

        if abs(z_dwell) > _Z_FLAG_THRESHOLD:
            direction = "above" if z_dwell > 0 else "below"
            factors.append(
                f"Dwell time {obs_dwell:.0f}s is {abs(z_dwell):.1f}x {direction} "
                f"normal for this hour"
            )

        if abs(z_entries) > _Z_FLAG_THRESHOLD:
            direction = "above" if z_entries > 0 else "below"
            factors.append(
                f"Zone entries {obs_entries:.0f} is {abs(z_entries):.1f}σ {direction} "
                f"baseline for {hour:02d}:00"
            )

        # Add rule-triggered event factors
        for event in events:
            etype = event.get("event_type", "unknown")
            factors.append(f"Event: {etype} (rule-triggered)")

        # --- Compute final score ---
        total_z = abs(z_person) + abs(z_vehicle) + abs(z_dwell) + abs(z_entries)
        baseline_score = min(100.0, max(0.0, total_z * _SCORE_PER_Z_UNIT))

        logger.debug(
            "AnomalyScorer camera=%s hour=%d z={person=%.2f, vehicle=%.2f, dwell=%.2f, entries=%.2f} "
            "score=%.1f",
            self.camera_id, hour, z_person, z_vehicle, z_dwell, z_entries, baseline_score,
        )

        return {
            "score": round(baseline_score, 2),
            "factors": factors,
            "z_scores": z_scores,
            "is_baseline_active": True,
        }
