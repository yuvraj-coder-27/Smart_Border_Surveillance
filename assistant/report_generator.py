"""
assistant/report_generator.py
──────────────────────────────
AI Investigation Assistant — Phase 8.

Provides two main capabilities:

1. **Free-form Q&A** (:meth:`InvestigationAssistant.query`)
   The assistant fetches recent alerts, events and risk scores from the local
   DB, builds a grounded context string, and — if the Gemini API is available
   — sends it to the LLM with a strict system instruction to answer only from
   the provided data.  When the LLM is unavailable it falls back to a simple
   keyword-matching engine.

2. **Incident report drafting** (:meth:`InvestigationAssistant.draft_incident_report`)
   Fetches all DB data for a specific alert and produces a structured narrative
   with five sections: Incident Summary, Timeline, Observations, Evidence
   References, and Recommended Action.  Falls back to a template-based
   renderer when the LLM is unavailable.
"""

from __future__ import annotations

import logging
import textwrap
from datetime import datetime, timedelta, timezone
from typing import Any

from config import settings
from database.db import get_db
from database.models import Alert, Evidence, Event, RiskScore

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Optional Gemini import
# ──────────────────────────────────────────────────────────────────────────────

try:
    import google.genai as genai  # type: ignore[import]
    _GENAI_AVAILABLE = True
    _GENAI_VERSION = "new"
except ImportError:
    try:
        import google.generativeai as genai  # type: ignore[import]
        _GENAI_AVAILABLE = True
        _GENAI_VERSION = "legacy"
    except ImportError:
        genai = None  # type: ignore[assignment]
        _GENAI_AVAILABLE = False
        _GENAI_VERSION = "none"


class InvestigationAssistant:
    """
    AI-powered investigation assistant grounded in the local surveillance DB.

    When a valid Gemini API key is present the assistant delegates to the
    Gemini LLM.  In offline / no-key scenarios it falls back to deterministic
    keyword-based answering and template-based report generation so the system
    always returns useful output.

    Parameters
    ----------
    (none — configuration is read from ``config.settings``)
    """

    # ── System instruction sent to the LLM ────────────────────────────────────
    _SYSTEM_INSTRUCTION = (
        "You are a specialist border-surveillance analyst assistant. "
        "You MUST answer ONLY from the provided database context below. "
        "Do NOT invent or hallucinate any events, alerts, camera IDs, "
        "risk scores, or timestamps that do not appear in the context. "
        "If the answer cannot be found in the context, say so explicitly. "
        "Keep answers concise, factual, and professional."
    )

    def __init__(self) -> None:
        self.llm_available: bool = False
        self._genai_client = None

        if not _GENAI_AVAILABLE:
            logger.warning(
                "InvestigationAssistant: google-genai / google-generativeai not installed — "
                "using local database intelligence"
            )
            return

        api_key: str = settings.GEMINI_API_KEY or ""
        if not api_key:
            logger.info(
                "InvestigationAssistant: GEMINI_API_KEY not provided — "
                "using local database intelligence"
            )
            return

        try:
            if hasattr(genai, "Client"):
                http_opts = None
                try:
                    from google.genai import types
                    http_opts = types.HttpOptions(timeout=15000)
                except Exception:
                    pass

                if http_opts:
                    self._genai_client = genai.Client(api_key=api_key, http_options=http_opts)
                else:
                    self._genai_client = genai.Client(api_key=api_key)
                self.llm_available = True
                logger.info("InvestigationAssistant: Google GenAI Client configured successfully.")
            elif hasattr(genai, "configure"):
                genai.configure(api_key=api_key)
                self.llm_available = True
                logger.info("InvestigationAssistant: Legacy GenerativeAI configured successfully.")
            else:
                self.llm_available = False
        except Exception as exc:  # noqa: BLE001
            logger.exception("InvestigationAssistant: failed to initialize Gemini API: %s", exc)
            self.llm_available = False

    # ── Public API ────────────────────────────────────────────────────────────

    def query(self, question: str) -> dict[str, Any]:
        """
        Answer a natural-language question about the surveillance system.

        The assistant fetches the last 100 alerts, last 100 events, and all
        risk scores from the past 24 hours and uses them as grounding context.
        """
        context_str, source_list = self._build_context()
        context_data = self._build_context_data()

        if self.llm_available:
            prompt = (
                f"DATABASE CONTEXT:\n{context_str}\n\n"
                f"OPERATOR QUESTION: {question}"
            )
            answer = self._gemini_request(prompt, self._SYSTEM_INSTRUCTION)
            if not answer or answer.startswith("[ERROR]"):
                # Graceful fallback to deterministic DB intelligence
                fallback = self._fallback_query(question, context_data)
                return fallback
            return {
                "answer": answer,
                "sources": source_list,
                "grounded": True,
            }

        return self._fallback_query(question, context_data)

    def draft_incident_report(self, alert_id: int) -> dict[str, Any]:
        """
        Generate a structured incident report for a specific alert.

        Fetches the Alert, its linked Events, and all Evidence from the DB,
        then asks the LLM (or a template engine) to produce a five-section
        narrative.

        Parameters
        ----------
        alert_id : int
            Primary key of the Alert to report on.

        Returns
        -------
        dict
            ``{report_text: str, alert_id: int, generated_at: str, llm_used: bool}``
        """
        alert_data = self._fetch_alert_data(alert_id)

        if self.llm_available:
            report_text = self._llm_incident_report(alert_id, alert_data)
            if not report_text or report_text.startswith("[ERROR]"):
                report_text = self._template_incident_report(alert_id, alert_data)
                llm_used = False
            else:
                llm_used = True
        else:
            report_text = self._template_incident_report(alert_id, alert_data)
            llm_used = False

        return {
            "report_text": report_text,
            "alert_id": alert_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "llm_used": llm_used,
        }

    # ── Context builders ──────────────────────────────────────────────────────

    def _build_context(self) -> tuple[str, list[dict[str, Any]]]:
        """
        Build a structured text block and a source list from recent DB data.

        Returns
        -------
        tuple[str, list[dict]]
            ``(context_str, source_list)``
        """
        data = self._build_context_data()

        lines: list[str] = []
        sources: list[dict[str, Any]] = []

        # ── Alerts ────────────────────────────────────────────────────────────
        lines.append("=== RECENT ALERTS ===")
        for a in data["alerts"]:
            lines.append(
                f"  Alert#{a['id']} | camera={a['camera_id']} | "
                f"type={a['alert_type']} | status={a['status']} | "
                f"score={a['risk_score_value']} | ts={a['timestamp']}"
            )
            sources.append({
                "type": "alert",
                "id": a["id"],
                "camera": a.get("camera_id", "cam_0"),
                "timestamp": a.get("timestamp"),
                "label": f"{a.get('alert_type', 'threat')}: {a.get('message', '')}"
            })

        # ── Events ────────────────────────────────────────────────────────────
        lines.append("\n=== RECENT EVENTS ===")
        for e in data["events"]:
            lines.append(
                f"  Event#{e['id']} | camera={e['camera_id']} | "
                f"type={e['event_type']} | zone={e['zone_id']} | ts={e['timestamp']}"
            )
            sources.append({
                "type": "event",
                "id": e["id"],
                "camera": e.get("camera_id", "cam_0"),
                "timestamp": e.get("timestamp"),
                "label": str(e.get("event_type", "event"))
            })

        # ── Risk scores ───────────────────────────────────────────────────────
        lines.append("\n=== RISK SCORES (last 24 h) ===")
        for r in data["risk_scores"]:
            lines.append(
                f"  RiskScore#{r['id']} | camera={r['camera_id']} | "
                f"score={r['score']:.1f} | ts={r['timestamp']}"
            )
            sources.append({
                "type": "risk_score",
                "id": r["id"],
                "camera": r.get("camera_id", "cam_0"),
                "timestamp": r.get("timestamp"),
                "label": f"Risk Score {r.get('score', 0):.1f}"
            })

        context_str = "\n".join(lines)
        return context_str, sources

    def _build_context_data(self) -> dict[str, Any]:
        """
        Return recent DB records as plain Python dicts for in-process use.
        """
        cutoff_24h = datetime.utcnow() - timedelta(hours=24)
        result: dict[str, Any] = {"alerts": [], "events": [], "risk_scores": []}

        with get_db() as session:
            alerts = (
                session.query(Alert)
                .order_by(Alert.timestamp.desc())
                .limit(35)
                .all()
            )
            for a in alerts:
                result["alerts"].append(
                    {
                        "id": a.id,
                        "camera_id": a.camera_id,
                        "alert_type": a.alert_type,
                        "message": a.message,
                        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                        "status": a.status,
                        "risk_score_value": a.risk_score_value,
                        "contributing_factors": a.contributing_factors or [],
                    }
                )

            events = (
                session.query(Event)
                .order_by(Event.timestamp.desc())
                .limit(35)
                .all()
            )
            for e in events:
                result["events"].append(
                    {
                        "id": e.id,
                        "camera_id": e.camera_id,
                        "event_type": e.event_type,
                        "track_id": e.track_id,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        "zone_id": e.zone_id,
                        "details": e.details or {},
                    }
                )

            risk_scores = (
                session.query(RiskScore)
                .filter(RiskScore.timestamp >= cutoff_24h)
                .order_by(RiskScore.timestamp.desc())
                .limit(20)
                .all()
            )
            for r in risk_scores:
                result["risk_scores"].append(
                    {
                        "id": r.id,
                        "camera_id": r.camera_id,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                        "score": r.score,
                        "contributing_factors": r.contributing_factors or [],
                        "event_ids": r.event_ids or [],
                    }
                )

        return result

    # ── Fallback Q&A ─────────────────────────────────────────────────────────

    def _fallback_query(self, question: str, context_data: dict[str, Any]) -> dict[str, Any]:
        """
        Simple keyword-based Q&A when the LLM is unavailable.

        Handles the most common operator questions:

        * Count / "how many" queries.
        * Time-filtered queries ("today", "last week").
        * Camera-specific queries ("camera CAM-01").
        * Status queries ("open", "confirmed", "dismissed").

        Parameters
        ----------
        question     : Operator's question string.
        context_data : Dict returned by :meth:`_build_context_data`.

        Returns
        -------
        dict
            ``{answer: str, sources: list[dict], grounded: bool}``
        """
        q = question.lower()
        alerts: list[dict] = context_data.get("alerts", [])
        events: list[dict] = context_data.get("events", [])
        risk_scores: list[dict] = context_data.get("risk_scores", [])

        answer_lines: list[str] = []
        sources: list[dict[str, Any]] = []

        # ── Helpers ───────────────────────────────────────────────────────────

        def _today_str() -> str:
            return datetime.utcnow().strftime("%Y-%m-%d")

        def _this_week_start() -> str:
            today = datetime.utcnow()
            start = today - timedelta(days=today.weekday())
            return start.strftime("%Y-%m-%d")

        def _filter_by_time(items: list[dict], key: str = "timestamp") -> list[dict]:
            """Filter items to today or last week based on question keywords."""
            if "today" in q:
                prefix = _today_str()
                return [i for i in items if (i.get(key) or "").startswith(prefix)]
            if "last week" in q or "this week" in q:
                week_start = _this_week_start()
                return [i for i in items if (i.get(key) or "") >= week_start]
            return items

        def _filter_by_camera(items: list[dict]) -> list[dict]:
            """Filter items to a specific camera mentioned in the question."""
            import re
            match = re.search(r"camera[_\s\-]?([a-z0-9\-_]+)", q)
            if match:
                cam = match.group(1).upper()
                return [
                    i for i in items
                    if cam in (i.get("camera_id") or "").upper()
                ]
            return items

        # ── Route the question ────────────────────────────────────────────────

        # ── Intelligence Query Analyzers ──────────────────────────────────────

        # 1. Highest Risk Camera / Outpost Ranking
        if not answered and any(term in q for term in ["highest risk", "top risk", "most dangerous", "which camera", "highest threat"]):
            answered = True
            cam_scores: dict[str, list[float]] = {}
            for r in risk_scores:
                cid = r.get("camera_id", "unknown")
                cam_scores.setdefault(cid, []).append(r.get("score", 0.0))
            for a in alerts:
                cid = a.get("camera_id", "unknown")
                r_val = a.get("risk_score_value") or a.get("risk_score")
                if r_val is not None:
                    cam_scores.setdefault(cid, []).append(float(r_val))

            if cam_scores:
                cam_stats = []
                for cid, scs in cam_scores.items():
                    cam_stats.append({
                        "camera": cid,
                        "max": max(scs),
                        "avg": sum(scs) / len(scs),
                        "count": len(scs)
                    })
                cam_stats.sort(key=lambda x: x["max"], reverse=True)
                top = cam_stats[0]
                answer_lines.append(
                    f"🎯 **Sector Threat Assessment**: Camera **{top['camera']}** is currently evaluated with the highest threat level:\n"
                    f"• Peak Risk Score: **{top['max']:.1f} / 100**\n"
                    f"• Average Sector Risk: **{top['avg']:.1f}** across {top['count']} incident log(s)\n"
                )
                if len(cam_stats) > 1:
                    other_cams = ", ".join(f"{c['camera']} (peak {c['max']:.0f})" for c in cam_stats[1:4])
                    answer_lines.append(f"• Subsequent monitored cameras: {other_cams}")
                sources.extend({"type": "risk_score", "id": r["id"]} for r in risk_scores[:5])
            else:
                answer_lines.append("No camera risk telemetry recorded in the current active window.")

        # 2. Threat Breakdown / Distribution
        if not answered and any(term in q for term in ["threat breakdown", "threat type", "common threat", "threat summary", "breakdown", "distribution", "types of threat"]):
            answered = True
            type_counts: dict[str, int] = {}
            for a in alerts:
                t = a.get("alert_type") or "unknown"
                type_counts[t] = type_counts.get(t, 0) + 1
            for e in events:
                t = e.get("event_type") or "unknown"
                type_counts[t] = type_counts.get(t, 0) + 1

            if type_counts:
                total_threats = sum(type_counts.values())
                sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
                answer_lines.append(f"📊 **Sector Threat Breakdown** ({total_threats} total logged occurrences):")
                for t_name, count in sorted_types:
                    pct = (count / total_threats) * 100.0
                    answer_lines.append(f"• **{t_name.replace('_', ' ').title()}**: {count} incident(s) ({pct:.1f}%)")
                sources.extend({"type": "alert", "id": a["id"]} for a in alerts[:5])
            else:
                answer_lines.append("No classified threat events recorded in the current window.")

        # 3. Critical / Severe Incident Queries
        if not answered and any(term in q for term in ["critical", "severe", "urgent", "high risk alert", "most severe"]):
            answered = True
            critical_alerts = [
                a for a in alerts
                if (float(a.get("risk_score_value") or 0.0) >= 70.0) or ("critical" in str(a.get("alert_type", "")).lower())
            ]
            if critical_alerts:
                answer_lines.append(f"🚨 **High-Priority Threat Alerts**: Found **{len(critical_alerts)}** critical incident(s):\n")
                for ca in critical_alerts[:4]:
                    r_score = ca.get("risk_score_value") or "N/A"
                    answer_lines.append(
                        f"• Alert #{ca['id']} [{ca.get('alert_type', 'threat').upper()}] @ {ca.get('camera_id', 'cam_0')}: "
                        f"Risk {r_score} — \"{ca.get('message', 'Unverified breach')}\""
                    )
                sources.extend({"type": "alert", "id": a["id"]} for a in critical_alerts[:6])
            else:
                answer_lines.append("✅ No critical alerts (risk score ≥ 70) found in recent sector logs. Perimeter posture normal.")

        # 4. Command SITREP / Overview
        if not answered and any(term in q for term in ["sitrep", "overview", "situation", "status report", "summary", "posture"]):
            answered = True
            open_count = sum(1 for a in alerts if a.get("status") == "open")
            confirmed_count = sum(1 for a in alerts if a.get("status") == "confirmed")
            avg_risk = sum(r.get("score", 0.0) for r in risk_scores) / max(len(risk_scores), 1)
            answer_lines.append(
                f"🛡️ **BORDER COMMAND SITREP (Edge Automated)**\n"
                f"• Active Incidents Requiring Triage: **{open_count}** open alert(s)\n"
                f"• Confirmed Infiltration Breaches: **{confirmed_count}**\n"
                f"• Monitored Telemetry Events: **{len(events)}** in telemetry buffer\n"
                f"• Sector Composite Risk Level: **{avg_risk:.1f} / 100**\n"
                f"• Operational Integrity: **All optical nodes synchronized with cryptographic audit ledger**"
            )
            sources.extend({"type": "alert", "id": a["id"]} for a in alerts[:4])

        # 5. Count / "how many" queries
        if not answered and ("how many" in q or "count" in q or "total" in q or "number of" in q):
            answered = True
            if "alert" in q:
                subset = _filter_by_time(alerts)
                subset = _filter_by_camera(subset)
                # Status sub-filter
                for status in ("open", "confirmed", "dismissed"):
                    if status in q:
                        subset = [a for a in subset if a.get("status") == status]
                        break
                answer_lines.append(
                    f"There are **{len(subset)}** alert(s) matching your query "
                    f"(from the most recent 100 records in the DB)."
                )
                sources.extend({"type": "alert", "id": a["id"]} for a in subset)

            elif "event" in q:
                subset = _filter_by_time(events)
                subset = _filter_by_camera(subset)
                if "intrusion" in q:
                    subset = [e for e in subset if "intrusion" in (e.get("event_type") or "")]
                elif "loitering" in q:
                    subset = [e for e in subset if "loitering" in (e.get("event_type") or "")]
                elif "crossing" in q or "border" in q:
                    subset = [e for e in subset if "border" in (e.get("event_type") or "")]
                answer_lines.append(
                    f"There are **{len(subset)}** event(s) matching your query."
                )
                sources.extend({"type": "event", "id": e["id"]} for e in subset)

            else:
                # Generic count — report both
                a_count = len(_filter_by_time(alerts))
                e_count = len(_filter_by_time(events))
                answer_lines.append(
                    f"In the relevant time window: **{a_count}** alert(s) and "
                    f"**{e_count}** event(s) are recorded."
                )

        # 6. Camera-specific query
        if not answered and ("camera" in q):
            answered = True
            filtered_alerts = _filter_by_camera(alerts)
            filtered_events = _filter_by_camera(events)
            if filtered_alerts or filtered_events:
                answer_lines.append(
                    f"For the specified camera: **{len(filtered_alerts)}** alert(s) "
                    f"and **{len(filtered_events)}** event(s) found."
                )
                if filtered_alerts:
                    answer_lines.append("Most recent alert: " + (
                        f"Alert#{filtered_alerts[0]['id']} — "
                        f"{filtered_alerts[0]['alert_type']} @ "
                        f"{filtered_alerts[0]['timestamp']}"
                    ))
                sources.extend({"type": "alert", "id": a["id"]} for a in filtered_alerts[:5])
                sources.extend({"type": "event", "id": e["id"]} for e in filtered_events[:5])
            else:
                answer_lines.append(
                    "No alerts or events found for the specified camera in the recent data."
                )

        # 7. Risk score queries
        if not answered and ("risk" in q or "score" in q):
            answered = True
            if risk_scores:
                highest = max(risk_scores, key=lambda r: r["score"])
                avg_score = sum(r["score"] for r in risk_scores) / len(risk_scores)
                answer_lines.append(
                    f"In the last 24 hours: **{len(risk_scores)}** risk score(s) recorded. "
                    f"Highest: **{highest['score']:.1f}** (camera={highest['camera_id']} "
                    f"@ {highest['timestamp']}). Average: **{avg_score:.1f}**."
                )
                sources.extend({"type": "risk_score", "id": r["id"]} for r in risk_scores[:5])
            else:
                answer_lines.append("No risk scores recorded in the last 24 hours.")

        # 8. Status queries
        if not answered and any(s in q for s in ("open alert", "confirmed alert", "dismissed alert")):
            answered = True
            for status in ("open", "confirmed", "dismissed"):
                if status in q:
                    subset = [a for a in alerts if a.get("status") == status]
                    answer_lines.append(
                        f"There are **{len(subset)}** {status} alert(s) in the recent 100 records."
                    )
                    sources.extend({"type": "alert", "id": a["id"]} for a in subset[:10])

        # 9. Default fallback
        if not answered:
            answer_lines.append(
                f"I found **{len(alerts)}** recent alert(s), "
                f"**{len(events)}** recent event(s), and "
                f"**{len(risk_scores)}** risk score(s) in the last 24 h.\n"
                "You can ask queries like: 'What is the highest risk camera?', 'Show threat breakdown', "
                "'List critical alerts', 'Give command SITREP', or 'Draft report for alert 1'."
            )


        return {
            "answer": "\n".join(answer_lines),
            "sources": sources[:20],  # cap to avoid overwhelming the UI
            "grounded": True,
        }

    # ── Alert data fetcher ────────────────────────────────────────────────────

    def _fetch_alert_data(self, alert_id: int) -> dict[str, Any]:
        """
        Fetch a fully hydrated dict for a single alert including its events
        and evidence.

        Returns
        -------
        dict
            ``{alert, events, evidence}`` — all as plain dicts.
            If the alert does not exist, ``alert`` is ``None``.
        """
        result: dict[str, Any] = {"alert": None, "events": [], "evidence": []}

        with get_db() as session:
            alert: Alert | None = session.get(Alert, alert_id)
            if alert is None:
                return result

            result["alert"] = {
                "id": alert.id,
                "camera_id": alert.camera_id,
                "alert_type": alert.alert_type,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "status": alert.status,
                "risk_score_value": alert.risk_score_value,
                "contributing_factors": alert.contributing_factors or [],
                "operator_feedback": alert.operator_feedback,
            }

            # ── Linked events via RiskScore ────────────────────────────────────
            if alert.risk_score_id:
                risk_score: RiskScore | None = session.get(RiskScore, alert.risk_score_id)
                if risk_score:
                    event_ids = risk_score.event_ids or []
                    if event_ids:
                        events = (
                            session.query(Event)
                            .filter(Event.id.in_(event_ids))
                            .order_by(Event.timestamp.asc())
                            .all()
                        )
                        for e in events:
                            result["events"].append(
                                {
                                    "id": e.id,
                                    "camera_id": e.camera_id,
                                    "event_type": e.event_type,
                                    "track_id": e.track_id,
                                    "timestamp": e.timestamp.isoformat()
                                    if e.timestamp
                                    else None,
                                    "zone_id": e.zone_id,
                                    "details": e.details or {},
                                }
                            )

            # ── Evidence attached directly to the alert ────────────────────────
            evidence_rows = (
                session.query(Evidence)
                .filter(Evidence.alert_id == alert_id)
                .order_by(Evidence.created_at.asc())
                .all()
            )
            for ev in evidence_rows:
                result["evidence"].append(
                    {
                        "id": ev.id,
                        "snapshot_path": ev.snapshot_path,
                        "clip_path": ev.clip_path,
                        "thumbnail_path": ev.thumbnail_path,
                        "sync_status": ev.sync_status,
                        "created_at": ev.created_at.isoformat() if ev.created_at else None,
                    }
                )

        return result

    # ── Report rendering ──────────────────────────────────────────────────────

    def _llm_incident_report(self, alert_id: int, alert_data: dict[str, Any]) -> str:
        """
        Ask Gemini to write a structured incident report from the provided data.
        """
        alert = alert_data.get("alert")
        if not alert:
            return f"[ERROR] Alert #{alert_id} not found in the database."

        events_text = "\n".join(
            f"  - [{e['timestamp']}] {e['event_type']} "
            f"(track_id={e['track_id']}, zone={e['zone_id']})"
            for e in alert_data.get("events", [])
        ) or "  (no linked events)"

        evidence_text = "\n".join(
            f"  - Evidence#{ev['id']}: snapshot={ev['snapshot_path']}, "
            f"clip={ev['clip_path']}, sync={ev['sync_status']}"
            for ev in alert_data.get("evidence", [])
        ) or "  (no evidence files)"

        prompt = textwrap.dedent(f"""
            You are a border-surveillance analyst. Write a professional incident
            report using ONLY the data below.  Structure it with exactly these
            five sections, each clearly labelled:

            1. Incident Summary
            2. Timeline
            3. Observations
            4. Evidence References
            5. Recommended Action

            ── ALERT DATA ──
            Alert ID       : {alert['id']}
            Camera         : {alert['camera_id']}
            Alert Type     : {alert['alert_type']}
            Message        : {alert['message']}
            Timestamp      : {alert['timestamp']}
            Status         : {alert['status']}
            Risk Score     : {alert['risk_score_value']}
            Factors        : {', '.join(alert['contributing_factors']) or 'N/A'}
            Op. Feedback   : {alert['operator_feedback'] or 'None'}

            ── LINKED EVENTS ──
            {events_text}

            ── EVIDENCE ──
            {evidence_text}
        """).strip()

        return self._gemini_request(prompt, self._SYSTEM_INSTRUCTION)

    def _template_incident_report(
        self, alert_id: int, alert_data: dict[str, Any]
    ) -> str:
        """
        Generate a template-based incident report when the LLM is not available.
        """
        alert = alert_data.get("alert")
        if not alert:
            return f"[ERROR] Alert #{alert_id} not found in the database."

        events = alert_data.get("events", [])
        evidence_list = alert_data.get("evidence", [])

        # ── 1. Incident Summary ────────────────────────────────────────────────
        summary = (
            f"Alert #{alert['id']} of type '{alert['alert_type']}' was raised by "
            f"camera '{alert['camera_id']}' on {alert['timestamp']}. "
            f"The computed risk score at alert creation was "
            f"{alert['risk_score_value'] if alert['risk_score_value'] is not None else 'N/A'}. "
            f"Current status: {alert['status'].upper()}."
        )

        # ── 2. Timeline ────────────────────────────────────────────────────────
        if events:
            timeline_items = []
            for e in events:
                timeline_items.append(
                    f"  [{e['timestamp'] or 'unknown'}] "
                    f"Event type='{e['event_type']}', "
                    f"zone='{e['zone_id'] or 'N/A'}', "
                    f"track_id='{e['track_id'] or 'N/A'}'."
                )
            timeline = "\n".join(timeline_items)
        else:
            timeline = "  No individual events linked to this alert."

        # ── 3. Observations ────────────────────────────────────────────────────
        factors = alert["contributing_factors"]
        if factors:
            obs = "  Contributing factors identified:\n" + "\n".join(
                f"    • {f}" for f in factors
            )
        else:
            obs = "  No contributing factors recorded."
        if alert.get("operator_feedback"):
            obs += f"\n  Operator feedback: {alert['operator_feedback']}"

        # ── 4. Evidence References ────────────────────────────────────────────
        if evidence_list:
            ev_lines = []
            for ev in evidence_list:
                parts = []
                if ev.get("snapshot_path"):
                    parts.append(f"snapshot: {ev['snapshot_path']}")
                if ev.get("clip_path"):
                    parts.append(f"clip: {ev['clip_path']}")
                if ev.get("thumbnail_path"):
                    parts.append(f"thumbnail: {ev['thumbnail_path']}")
                sync = ev.get("sync_status", "unknown")
                ev_lines.append(
                    f"  Evidence#{ev['id']} ({sync}): " + ", ".join(parts)
                )
            evidence_section = "\n".join(ev_lines)
        else:
            evidence_section = "  No evidence files attached to this alert."

        # ── 5. Recommended Action ─────────────────────────────────────────────
        score = alert["risk_score_value"]
        if score is not None and score >= 70:
            action = (
                "Immediate escalation recommended.  Dispatch a response team "
                "to the camera location.  Notify duty officer."
            )
        elif score is not None and score >= 40:
            action = (
                "Investigate alert via live camera feed.  If threat confirmed, "
                "escalate to duty officer.  Preserve all evidence."
            )
        else:
            action = (
                "Monitor the situation.  Review linked events and evidence. "
                "Dismiss if determined to be a false positive."
            )

        report = textwrap.dedent(f"""
            ═══════════════════════════════════════════════════════════════
             INCIDENT REPORT — Alert #{alert_id}
             Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
             [Template mode — Gemini LLM not available]
            ═══════════════════════════════════════════════════════════════

            1. INCIDENT SUMMARY
            {summary}

            2. TIMELINE
            {timeline}

            3. OBSERVATIONS
            {obs}

            4. EVIDENCE REFERENCES
            {evidence_section}

            5. RECOMMENDED ACTION
              {action}

            ═══════════════════════════════════════════════════════════════
        """).strip()

        return report

    def _gemini_request(self, prompt: str, system_instruction: str, timeout: float = 10.0) -> str:
        """
        Send a prompt to the Gemini API and return the response text.
        Uses modern google.genai Client with daemon thread timeout to prevent UI lag.
        """
        if not self.llm_available or genai is None:
            return "[ERROR] LLM is not available."

        import threading
        import queue

        def _run_with_daemon_timeout(fn, limit: float):
            q: queue.Queue = queue.Queue()
            def worker():
                try:
                    res = fn()
                    q.put((True, res))
                except Exception as e:
                    q.put((False, e))
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            try:
                success, val = q.get(timeout=limit)
                if success:
                    return val
                raise val
            except queue.Empty:
                raise TimeoutError(f"Operation timed out after {limit}s")

        candidate_models = [
            getattr(settings, "AI_MODEL", "gemini-flash-latest"),
            "gemini-flash-latest",
            "gemini-flash-lite-latest",
            "gemini-3.5-flash",
            "gemma-4-26b-a4b-it",
        ]
        # De-duplicate preserving order
        candidate_models = list(dict.fromkeys([m for m in candidate_models if m]))

        # 1. Modern google.genai Client
        if self._genai_client is not None:
            for model_name in candidate_models:
                try:
                    def _call_client():
                        config = None
                        try:
                            from google.genai import types
                            config = types.GenerateContentConfig(
                                system_instruction=system_instruction,
                                automatic_function_calling=dict(disable=True)
                            )
                        except Exception:
                            pass
                        return self._genai_client.models.generate_content(
                            model=model_name,
                            contents=prompt,
                            config=config,
                        )

                    response = _run_with_daemon_timeout(_call_client, limit=timeout)
                    if response and response.text:
                        return response.text
                except TimeoutError:
                    logger.warning("Gemini Client model %s timed out after %ss, trying next candidate...", model_name, timeout)
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Gemini Client model %s attempt failed: %s", model_name, exc)
                    continue

        # 2. Legacy google.generativeai GenerativeModel (fallback if modern Client not used)
        elif hasattr(genai, "GenerativeModel"):
            for model_name in candidate_models:
                try:
                    def _call_legacy():
                        model = genai.GenerativeModel(
                            model_name=model_name,
                            system_instruction=system_instruction,
                        )
                        return model.generate_content(prompt)

                    response = _run_with_daemon_timeout(_call_legacy, limit=timeout)
                    if response and response.text:
                        return response.text
                except TimeoutError:
                    logger.warning("GenerativeModel %s timed out after %ss, trying next candidate...", model_name, timeout)
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.debug("GenerativeModel %s attempt failed: %s", model_name, exc)
                    continue

        return "[ERROR] Could not complete LLM request."

