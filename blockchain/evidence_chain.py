"""
blockchain/evidence_chain.py
=============================
High-level evidence chain API used by the rest of the system.

This module is the single integration point — all other modules call
``get_evidence_chain()`` and use its methods without knowing about the
underlying blockchain implementation.

Usage
-----
    from blockchain.evidence_chain import get_evidence_chain

    ec = get_evidence_chain()
    tx = ec.record_alert(alert_id=42, alert_dict={...})
    result = ec.verify_alert(alert_id=42, alert_dict={...})
    # result["verified"] → True / False
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from blockchain.hasher import hash_alert, hash_event, hash_file, hash_audit_action
from blockchain.local_chain import get_chain, Block

logger = logging.getLogger(__name__)


class EvidenceChain:
    """
    High-level wrapper around LocalChain that provides domain-specific
    record/verify methods for alerts, evidence, and audit actions.
    """

    def __init__(self):
        self._chain = get_chain()

    # ── Alert recording ───────────────────────────────────────────────────────

    def record_alert(self, alert_id: int, alert_dict: dict) -> dict:
        """
        Record an alert's content hash on the blockchain.

        Call this immediately after an alert is created so that any future
        database modification is detectable.

        Returns
        -------
        dict: {record_id, data_hash, block_index, block_hash, timestamp}
        """
        record_id = f"alert_{alert_id}"
        if self._chain.get_block_by_record(record_id):
            logger.debug(f"Alert {alert_id} already on chain — skipping duplicate")
            return self.get_record_info(record_id)

        data_hash = hash_alert(alert_dict)
        block = self._chain.add_record("alert", record_id, data_hash)
        logger.info(f"Alert {alert_id} committed to blockchain (block #{block.index})")
        return _block_to_result(block)

    def verify_alert(self, alert_id: int, alert_dict: dict) -> dict:
        """
        Verify that the current alert data matches what was committed.

        Returns
        -------
        dict with verified (bool), message, block_index, block_hash, etc.
        """
        record_id = f"alert_{alert_id}"
        current_hash = hash_alert(alert_dict)
        result = self._chain.verify_record(record_id, current_hash)
        result["alert_id"] = alert_id
        return result

    def commit_alert(
        self,
        alert_id: int,
        camera_id: str = "",
        alert_type: str = "",
        risk_score: float = 0.0,
        evidence_path: Optional[str] = None,
        evidence_id: Optional[int] = None,
        metadata: Optional[dict] = None,
        timestamp: Optional[str] = None,
    ) -> dict:
        """
        Convenience method to commit a live alert and optional snapshot evidence to the chain.
        """
        metadata = metadata or {}
        alert_ts = timestamp or metadata.get("timestamp") or datetime.now(timezone.utc).isoformat()
        alert_dict = {
            "id": alert_id,
            "camera_id": camera_id,
            "alert_type": alert_type,
            "message": metadata.get("message", ""),
            "timestamp": alert_ts,
            "risk_score": risk_score,
            "risk_score_value": risk_score,
            "contributing_factors": metadata.get("contributing_factors", []),
        }
        res = self.record_alert(alert_id, alert_dict)
        if evidence_path:
            try:
                self.record_evidence(
                    evidence_id=evidence_id or alert_id,
                    alert_id=alert_id,
                    snapshot_path=evidence_path,
                    thumbnail_path=evidence_path,
                )
            except Exception as ee:
                logger.warning(f"Could not commit evidence for alert {alert_id}: {ee}")
        return res


    # ── Evidence (snapshots / clips) recording ────────────────────────────────

    def record_evidence(
        self,
        evidence_id: int,
        alert_id: Optional[int],
        snapshot_path: Optional[str],
        thumbnail_path: Optional[str],
    ) -> dict:
        """
        Hash a snapshot file and commit the hash to the chain.
        If no file path given, commits a placeholder hash.
        """
        record_id = f"evidence_{evidence_id}"
        file_hash = hash_file(snapshot_path or thumbnail_path or "")
        if not file_hash:
            # No physical file yet — commit metadata hash
            file_hash = hash_alert({
                "evidence_id": evidence_id,
                "alert_id": alert_id,
                "path": snapshot_path,
            })
        block = self._chain.add_record("evidence", record_id, file_hash)
        logger.info(f"Evidence {evidence_id} committed to blockchain (block #{block.index})")
        return _block_to_result(block)

    def verify_evidence(
        self,
        evidence_id: int,
        snapshot_path: Optional[str],
        thumbnail_path: Optional[str],
    ) -> dict:
        """Verify a snapshot file's hash against the blockchain record."""
        record_id = f"evidence_{evidence_id}"
        current_hash = hash_file(snapshot_path or thumbnail_path or "")
        result = self._chain.verify_record(record_id, current_hash)
        result["evidence_id"] = evidence_id
        return result

    # ── Audit action recording ────────────────────────────────────────────────

    def record_audit(
        self,
        action: str,
        entity_id: Any,
        details: dict,
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """
        Record an operator action (dismiss, confirm, zone-edit, etc.) immutably.

        These audit records can never be deleted — anyone reviewing the system
        can see who did what and when.
        """
        ts = timestamp or datetime.now(timezone.utc)
        record_id = f"audit_{action}_{entity_id}_{int(ts.timestamp())}"
        data_hash = hash_audit_action(action, entity_id, details, ts)
        block = self._chain.add_record("audit", record_id, data_hash)
        logger.info(f"Audit '{action}' on {entity_id} committed (block #{block.index})")
        return _block_to_result(block)

    # ── Chain-level operations ────────────────────────────────────────────────

    def verify_chain(self) -> dict:
        """Full integrity check of every block in the chain."""
        return self._chain.verify_chain()

    def get_stats(self) -> dict:
        return self._chain.get_stats()

    def get_recent_blocks(self, n: int = 20) -> list[dict]:
        return self._chain.get_recent_blocks(n)

    def get_record_info(self, record_id: str) -> dict:
        block = self._chain.get_block_by_record(record_id)
        return block or {}

    def reset_chain(self) -> dict:
        """Reset the chain to Genesis and return fresh stats."""
        self._chain.reset()
        return self._chain.get_stats()



# ── Helpers ───────────────────────────────────────────────────────────────────

def _block_to_result(block: Block) -> dict:
    return {
        "record_id":   block.record_id,
        "data_hash":   block.data_hash,
        "block_index": block.index,
        "block_hash":  block.block_hash,
        "timestamp":   block.timestamp,
    }


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[EvidenceChain] = None


def get_evidence_chain() -> EvidenceChain:
    global _instance
    if _instance is None:
        _instance = EvidenceChain()
    return _instance
