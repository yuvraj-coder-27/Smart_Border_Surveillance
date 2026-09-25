"""
analytics/event_fusion.py
Correlates recent events within a time window and produces a fused severity assessment.
"""

import logging
from typing import Literal

logger = logging.getLogger(__name__)

# Type alias for severity levels
Severity = Literal["low", "medium", "high", "critical"]


class EventFusion:
    """
    Combines multiple recent detection events into a single fused assessment
    that captures correlated threat indicators.

    The fusion output drives the risk engine and the operator dashboard.

    Severity decision tree
    ----------------------
    * **critical** — intrusion *and* loitering both present, OR ≥ 3 total events.
    * **high**     — intrusion present OR ≥ 2 total events.
    * **medium**   — loitering OR abandoned_object present.
    * **low**      — any single event of any type.

    Usage::

        fusion = EventFusion(camera_id="cam_01", time_window_seconds=60)
        result = fusion.fuse(recent_events=[...])
        # result = {event_counts, severity, correlated, summary}
    """

    def __init__(self, camera_id: str, time_window_seconds: int = 60) -> None:
        """
        Parameters
        ----------
        camera_id:            Camera identifier (used only in the summary string).
        time_window_seconds:  Informational window size referenced in summary text.
        """
        self.camera_id = camera_id
        self.time_window_seconds = time_window_seconds

    # ------------------------------------------------------------------
    # Core fusion
    # ------------------------------------------------------------------

    def fuse(self, recent_events: list[dict]) -> dict:
        """
        Fuse *recent_events* into a threat assessment dict.

        Parameters
        ----------
        recent_events: List of event dicts (each must have an ``event_type`` key).
                       These should already be filtered to the relevant time window
                       by the caller before being passed here.

        Returns
        -------
        dict with keys:

        * ``event_counts``  — {intrusion, loitering, abandoned_object,
                               border_crossing, other: int}
        * ``severity``      — 'low' | 'medium' | 'high' | 'critical'
        * ``correlated``    — True when >1 distinct event type is present
        * ``summary``       — human-readable description string
        """
        # --- Count events by type ---
        counts: dict[str, int] = {
            "intrusion": 0,
            "loitering": 0,
            "abandoned_object": 0,
            "border_crossing": 0,
            "vehicle_anpr": 0,
            "watchlist_vehicle": 0,
            "other": 0,
        }
        has_watchlist_hit = False
        for event in recent_events:
            etype = event.get("event_type", "other")
            if event.get("details", {}).get("is_watchlist_match") or etype == "watchlist_vehicle":
                counts["watchlist_vehicle"] += 1
                has_watchlist_hit = True
            elif etype in counts:
                counts[etype] += 1
            elif "vehicle" in etype or "anpr" in etype or "plate" in etype:
                counts["vehicle_anpr"] += 1
            else:
                counts["other"] += 1

        total_events: int = len(recent_events)
        distinct_types: set[str] = {
            e.get("event_type", "other") for e in recent_events
        }

        # --- Severity & Multimodal Correlation ---
        severity: Severity = self._compute_severity(counts, total_events, has_watchlist_hit)

        # Multimodal correlation: Vehicle presence + person breach or loitering
        is_multimodal = (counts["vehicle_anpr"] > 0 or counts["watchlist_vehicle"] > 0) and (
            counts["intrusion"] > 0 or counts["border_crossing"] > 0 or counts["loitering"] > 0
        )
        correlated: bool = len(distinct_types) > 1 or is_multimodal

        # --- Summary ---
        summary: str = self._build_summary(counts, severity, total_events, is_multimodal)

        result = {
            "event_counts": counts,
            "severity": severity,
            "correlated": correlated,
            "summary": summary,
        }
        logger.debug("EventFusion result for camera %s: %s", self.camera_id, result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_severity(
        self,
        counts: dict[str, int],
        total: int,
        has_watchlist_hit: bool = False,
    ) -> Severity:
        """Apply the severity decision tree with multimodal intelligence."""
        has_border_crossing = counts.get("border_crossing", 0) > 0
        has_intrusion = counts.get("intrusion", 0) > 0
        has_loitering = counts.get("loitering", 0) > 0
        has_abandoned = counts.get("abandoned_object", 0) > 0
        has_vehicle = (counts.get("vehicle_anpr", 0) + counts.get("watchlist_vehicle", 0)) > 0

        # Immediate Critical threats:
        # 1. Watchlist vehicle match
        # 2. Border crossing
        # 3. Multimodal vehicle + intrusion / loitering
        # 4. Intrusion + loitering compounding
        # 5. 3+ distinct events
        if (
            has_watchlist_hit
            or has_border_crossing
            or (has_vehicle and (has_intrusion or has_loitering))
            or (has_intrusion and has_loitering)
            or total >= 3
        ):
            return "critical"
        if has_intrusion or has_vehicle or total >= 2:
            return "high"
        if has_loitering or has_abandoned:
            return "medium"
        if total >= 1:
            return "low"
        return "low"

    def _build_summary(
        self,
        counts: dict[str, int],
        severity: Severity,
        total: int,
        is_multimodal: bool = False,
    ) -> str:
        """Compose a human-readable summary string."""
        if total == 0:
            return f"No events detected for Camera {self.camera_id}."

        # Collect descriptive phrases for present event types
        phrases: list[str] = []
        if counts.get("watchlist_vehicle", 0) > 0:
            phrases.append("Flagged Watchlist Vehicle")
        if counts.get("vehicle_anpr", 0) > 0:
            phrases.append("ANPR Vehicle Activity")
        if counts["intrusion"] > 0:
            phrases.append(
                f"Zone intrusion ×{counts['intrusion']}" if counts["intrusion"] > 1 else "Zone intrusion"
            )
        if counts["loitering"] > 0:
            phrases.append(
                f"loitering ×{counts['loitering']}" if counts["loitering"] > 1 else "loitering"
            )
        if counts["abandoned_object"] > 0:
            phrases.append(
                f"abandoned object ×{counts['abandoned_object']}"
                if counts["abandoned_object"] > 1
                else "abandoned object"
            )
        if counts["border_crossing"] > 0:
            phrases.append(
                f"border crossing ×{counts['border_crossing']}"
                if counts["border_crossing"] > 1
                else "border crossing"
            )
        if counts["other"] > 0:
            phrases.append(f"other event ×{counts['other']}")

        prefix = "MULTIMODAL CORRELATION: " if is_multimodal else ""
        joined = " + ".join(phrases)
        return (
            f"{prefix}{joined.capitalize()} detected at Camera {self.camera_id} "
            f"within {self.time_window_seconds}s window "
            f"[severity={severity}]"
        )
