"""
risk_engine/risk_scorer.py
Composite risk score computation from rule-based events, event fusion, and
the baseline anomaly signal.

The risk score is a weighted combination of:
  1. Rule-based component  — counts of specific event types
  2. Baseline component    — normalised anomaly z-score
  3. Fusion bonuses        — correlation and severity uplifts

Final score is clamped to [0, 100] and persisted to the ``risk_scores`` table.
"""

import json
import logging
from datetime import datetime
from typing import Literal

from config.settings import (
    RISK_WEIGHT_ABANDONED,
    RISK_WEIGHT_BASELINE_ZSCORE,
    RISK_WEIGHT_BORDER_CROSSING,
    RISK_WEIGHT_CRAWLING,
    RISK_WEIGHT_FENCE_TAMPERING,
    RISK_WEIGHT_INTRUSION,
    RISK_WEIGHT_LOITERING,
)
from database.db import get_db
from database.models import RiskScore

logger = logging.getLogger(__name__)

# Maximum number of each event type before its contribution is capped at 1.0
_MAX_PER_TYPE: int = 3

# Severity thresholds
_CRITICAL_THRESHOLD: float = 80.0
_HIGH_THRESHOLD: float = 50.0
_MEDIUM_THRESHOLD: float = 25.0

Severity = Literal["low", "medium", "high", "critical"]


class RiskScorer:
    """
    Computes a composite 0-100 risk score and persists it to the database.

    Score composition
    -----------------
    ::

        rule_score = (
              min(n_border     / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_BORDER_CROSSING
            + min(n_fence      / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_FENCE_TAMPERING
            + min(n_intrusions / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_INTRUSION
            + min(n_crawling   / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_CRAWLING
            + min(n_loitering  / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_LOITERING
            + min(n_abandoned  / MAX_PER_TYPE, 1.0) * RISK_WEIGHT_ABANDONED
        )

        baseline_component = anomaly_score / 100 * RISK_WEIGHT_BASELINE_ZSCORE

        fusion_bonus = 0
        if fusion['correlated']:  fusion_bonus += 10
        if fusion['severity'] == 'critical':  fusion_bonus += 15

        total = clamp(rule_score + baseline_component + fusion_bonus, 0, 100)

    Severity thresholds
    -------------------
    * critical ≥ 80
    * high     ≥ 50
    * medium   ≥ 25
    * low      < 25

    Usage::

        scorer = RiskScorer(camera_id="cam_01")
        result = scorer.compute(events=recent_events, fusion=fusion_dict, anomaly=anomaly_dict)
        print(result["score"], result["severity"])
    """

    def __init__(self, camera_id: str) -> None:
        """
        Parameters
        ----------
        camera_id: Camera identifier for DB persistence.
        """
        self.camera_id = camera_id

    # ------------------------------------------------------------------
    # Core computation
    # ------------------------------------------------------------------

    def calculate_score(
        self,
        events: list[dict],
        fusion: dict,
        anomaly: dict,
    ) -> dict:
        """
        Pure calculation of composite risk score without database persistence.

        Returns
        -------
        Dict with keys:
        * ``score``               — float 0-100
        * ``contributing_factors`` — deduplicated list[str]
        * ``severity``            — 'low' | 'medium' | 'high' | 'critical'
        * ``rule_score``          — float
        * ``baseline_component``  — float
        * ``fusion_bonus``        — float
        """
        # --- Rule-based score component ---
        n_border = sum(1 for e in events if e.get("event_type") == "border_crossing")
        n_fence = sum(1 for e in events if e.get("event_type") == "fence_tampering")
        n_intrusions = sum(1 for e in events if e.get("event_type") == "intrusion")
        n_crawling = sum(1 for e in events if e.get("event_type") == "crawling")
        n_loitering = sum(1 for e in events if e.get("event_type") == "loitering")
        n_abandoned = sum(1 for e in events if e.get("event_type") == "abandoned_object")
        n_watchlist = sum(
            1 for e in events
            if e.get("details", {}).get("is_watchlist_match")
            or e.get("event_type") == "watchlist_vehicle"
        )
        n_vehicle = sum(
            1 for e in events
            if "vehicle" in e.get("event_type", "") or "anpr" in e.get("event_type", "")
        )

        rule_score = (
            min(n_border / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_BORDER_CROSSING
            + min(n_fence / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_FENCE_TAMPERING
            + min(n_intrusions / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_INTRUSION
            + min(n_crawling / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_CRAWLING
            + min(n_loitering / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_LOITERING
            + min(n_abandoned / _MAX_PER_TYPE, 1.0) * RISK_WEIGHT_ABANDONED
            + min(n_watchlist / _MAX_PER_TYPE, 1.0) * 45.0
            + min(n_vehicle / _MAX_PER_TYPE, 1.0) * 20.0
        )

        # --- Baseline / anomaly component ---
        anomaly_score = float(anomaly.get("score", 0.0))
        baseline_component = (anomaly_score / 100.0) * RISK_WEIGHT_BASELINE_ZSCORE

        # --- Fusion & Multimodal bonus ---
        fusion_bonus = 0.0
        if fusion.get("correlated", False):
            fusion_bonus += 10.0
        if fusion.get("severity") == "critical":
            fusion_bonus += 15.0
        if (n_watchlist > 0 or n_vehicle > 0) and (n_border > 0 or n_intrusions > 0 or n_loitering > 0):
            fusion_bonus += 15.0

        # --- Total ---
        total = max(0.0, min(100.0, rule_score + baseline_component + fusion_bonus))

        # --- Contributing factors (deduplicated, order-preserving) ---
        raw_factors: list[str] = []
        raw_factors.extend(anomaly.get("factors", []))
        fusion_summary = fusion.get("summary", "")
        if fusion_summary:
            raw_factors.append(fusion_summary)
        if n_watchlist > 0:
            raw_factors.append("Flagged Watchlist Vehicle Detected")
        for e in events:
            etype = e.get("event_type", "unknown")
            raw_factors.append(f"Event: {etype}")

        seen: set[str] = set()
        factors: list[str] = []
        for f in raw_factors:
            if f not in seen:
                seen.add(f)
                factors.append(f)

        # --- Severity label & Priority Tier ---
        severity = self._severity_label(total)
        if total >= 80.0:
            priority_tier = "CRITICAL"
        elif total >= 60.0:
            priority_tier = "HIGH"
        elif total >= 40.0:
            priority_tier = "ELEVATED"
        elif total >= 20.0:
            priority_tier = "GUARDED"
        else:
            priority_tier = "NORMAL"

        threat_list = []
        if n_border > 0:
            threat_list.append("Virtual Border Crossing")
        if n_fence > 0:
            threat_list.append("Perimeter Fence Tampering")
        if n_watchlist > 0:
            threat_list.append("Flagged Watchlist Vehicle")
        if n_intrusions > 0:
            threat_list.append("Restricted Zone Intrusion")
        if n_crawling > 0:
            threat_list.append("Prone/Crawling Intruder")
        if n_loitering > 0:
            threat_list.append("Prolonged Presence / Loitering")

        reasoning = (
            f"Priority [{priority_tier}] with Risk Score {round(total, 1)}/100: "
            + (", ".join(threat_list) if threat_list else "Routine perimeter telemetry")
            + (f" with +{round(baseline_component, 1)} off-hours baseline anomaly." if baseline_component > 5 else ".")
        )

        explainability = {
            "priority_tier": priority_tier,
            "score": round(total, 1),
            "breakdown": {
                "rule_score": round(rule_score, 1),
                "baseline_component": round(baseline_component, 1),
                "fusion_bonus": round(fusion_bonus, 1),
            },
            "active_threats": threat_list,
            "reasoning": reasoning,
        }

        return {
            "score": round(total, 2),
            "contributing_factors": factors,
            "severity": severity,
            "rule_score": round(rule_score, 2),
            "baseline_component": round(baseline_component, 2),
            "fusion_bonus": round(fusion_bonus, 2),
            "explainability": explainability,
        }

    def compute(
        self,
        events: list[dict],
        fusion: dict,
        anomaly: dict,
    ) -> dict:
        """
        Compute and persist a RiskScore.
        """
        calculated = self.calculate_score(events, fusion, anomaly)
        total = calculated["score"]
        factors = calculated["contributing_factors"]
        severity = calculated["severity"]
        explainability = calculated.get("explainability", {})

        # --- Persist to DB ---
        event_ids = [e["id"] for e in events if "id" in e]
        risk_score_id = self._persist(total, factors, event_ids, explainability)

        logger.info(
            "RiskScore computed: camera=%s score=%.1f severity=%s "
            "rule=%.1f baseline=%.1f fusion_bonus=%.1f id=%d",
            self.camera_id, total, severity,
            calculated["rule_score"], calculated["baseline_component"], calculated["fusion_bonus"], risk_score_id,
        )

        return {
            "score": total,
            "contributing_factors": factors,
            "severity": severity,
            "risk_score_id": risk_score_id,
            "explainability": explainability,
        }


    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _severity_label(self, score: float) -> Severity:
        """Map a numeric score to a severity string."""
        if score >= _CRITICAL_THRESHOLD:
            return "critical"
        if score >= _HIGH_THRESHOLD:
            return "high"
        if score >= _MEDIUM_THRESHOLD:
            return "medium"
        return "low"

    def _persist(self, score: float, factors: list[str], event_ids: list[int], explainability: dict = None) -> int:
        """Write a RiskScore row to the database and return its id."""
        with get_db() as session:
            risk_row = RiskScore(
                camera_id=self.camera_id,
                timestamp=datetime.utcnow(),
                score=score,
                contributing_factors=json.dumps(factors),
                event_ids=json.dumps(event_ids),
                explainability=json.dumps(explainability or {}),
            )
            session.add(risk_row)
            session.flush()
            row_id = risk_row.id
        return row_id
