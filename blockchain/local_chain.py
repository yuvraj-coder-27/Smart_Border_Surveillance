"""
blockchain/local_chain.py
==========================
A real, self-contained, hash-linked blockchain implemented in pure Python.

Architecture
------------
Each Block contains:
  - index           : sequential block number
  - timestamp       : UTC ISO string
  - record_type     : "alert" | "evidence" | "audit" | "genesis"
  - record_id       : canonical ID (e.g. "alert_42")
  - data_hash       : SHA-256 of the original record data
  - previous_hash   : hash of the previous block (cryptographic link)
  - nonce           : proof-of-work nonce
  - block_hash      : SHA-256 of all above fields combined

Tamper detection
----------------
If any stored record in the DB is modified, its data_hash recomputed and
compared against what the chain has recorded will differ → TAMPERED flag.

If any block in the chain itself is altered, the chain's hash-linking
breaks at that block → verify_chain() returns False.

Persistence
-----------
Chain is serialised to JSON at  data/blockchain/chain.json
and reloaded on startup.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHAIN_PATH = os.path.join(_BASE_DIR, "data", "blockchain", "chain.json")
_DIFFICULTY = 3          # PoW: block hash must start with this many zeros
_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Block
# ─────────────────────────────────────────────────────────────────────────────

class Block:
    """A single immutable block in the evidence chain."""

    def __init__(
        self,
        index: int,
        record_type: str,
        record_id: str,
        data_hash: str,
        previous_hash: str,
        timestamp: Optional[str] = None,
        nonce: int = 0,
        block_hash: Optional[str] = None,
    ):
        self.index = index
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.record_type = record_type
        self.record_id = record_id
        self.data_hash = data_hash
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.block_hash = block_hash or self._compute_hash()

    # ── Hashing ──────────────────────────────────────────────────────────────

    def _compute_hash(self) -> str:
        content = (
            f"{self.index}"
            f"{self.timestamp}"
            f"{self.record_type}"
            f"{self.record_id}"
            f"{self.data_hash}"
            f"{self.previous_hash}"
            f"{self.nonce}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def mine(self, difficulty: int = _DIFFICULTY) -> None:
        """Proof-of-Work: increment nonce until block_hash starts with difficulty zeros."""
        target = "0" * difficulty
        self.nonce = 0
        self.block_hash = self._compute_hash()
        while not self.block_hash.startswith(target):
            self.nonce += 1
            self.block_hash = self._compute_hash()

    def is_valid(self, difficulty: int = _DIFFICULTY) -> bool:
        return (
            self.block_hash == self._compute_hash()
            and self.block_hash.startswith("0" * difficulty)
        )

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "record_type":   self.record_type,
            "record_id":     self.record_id,
            "data_hash":     self.data_hash,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "block_hash":    self.block_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            index=d["index"],
            record_type=d["record_type"],
            record_id=d["record_id"],
            data_hash=d["data_hash"],
            previous_hash=d["previous_hash"],
            timestamp=d["timestamp"],
            nonce=d["nonce"],
            block_hash=d["block_hash"],
        )

    def __repr__(self) -> str:
        return (
            f"<Block #{self.index} type={self.record_type!r} "
            f"id={self.record_id!r} hash={self.block_hash[:12]}…>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# LocalChain
# ─────────────────────────────────────────────────────────────────────────────

class LocalChain:
    """
    Append-only, hash-linked, proof-of-work blockchain stored locally as JSON.

    Thread-safe — a single module-level lock protects all mutations.
    """

    def __init__(self, chain_path: str = _CHAIN_PATH, difficulty: int = _DIFFICULTY):
        self._path = chain_path
        self._difficulty = difficulty
        self._chain: list[Block] = []
        self._index: dict[str, Block] = {}   # record_id → Block (fast lookup)
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r") as f:
                    data = json.load(f)
                self._chain = [Block.from_dict(b) for b in data]
                self._index = {b.record_id: b for b in self._chain}
                logger.info(f"Blockchain loaded: {len(self._chain)} blocks from {self._path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load chain ({e}) — starting fresh")
        self._create_genesis()
        self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump([b.to_dict() for b in self._chain], f, indent=2)

    def _create_genesis(self) -> None:
        genesis = Block(
            index=0,
            record_type="genesis",
            record_id="genesis_0",
            data_hash="0" * 64,
            previous_hash="0" * 64,
        )
        genesis.mine(self._difficulty)
        self._chain = [genesis]
        self._index = {"genesis_0": genesis}
        logger.info("Genesis block mined")

    def reset(self) -> None:
        """Reset the blockchain to a fresh state with only the Genesis block."""
        with _LOCK:
            self._create_genesis()
            self._save()
            logger.info(f"Blockchain reset to Genesis block at {self._path}")

    # ── Public API ────────────────────────────────────────────────────────────


    def add_record(
        self,
        record_type: str,
        record_id: str,
        data_hash: str,
    ) -> Block:
        """
        Mine and append a new block to the chain.

        Parameters
        ----------
        record_type : "alert" | "evidence" | "audit"
        record_id   : e.g. "alert_42", "evidence_7", "audit_dismiss_42"
        data_hash   : SHA-256 hex string produced by blockchain.hasher

        Returns
        -------
        The newly mined Block.
        """
        with _LOCK:
            prev = self._chain[-1]
            block = Block(
                index=len(self._chain),
                record_type=record_type,
                record_id=record_id,
                data_hash=data_hash,
                previous_hash=prev.block_hash,
            )
            block.mine(self._difficulty)
            self._chain.append(block)
            self._index[record_id] = block
            self._save()
            logger.debug(f"Block mined: {block}")
            return block

    def verify_record(self, record_id: str, data_hash: str) -> dict:
        """
        Check whether a record's current data_hash matches what was committed.

        Returns
        -------
        dict with keys:
          verified      : bool
          on_chain_hash : str  (what the chain has)
          provided_hash : str  (what the caller computed now)
          block_index   : int | None
          block_hash    : str | None
          message       : human-readable status
        """
        block = self._index.get(record_id)
        if block is None:
            return {
                "verified": False,
                "on_chain_hash": "",
                "provided_hash": data_hash,
                "block_index": None,
                "block_hash": None,
                "message": f"No blockchain record found for '{record_id}'",
            }
        match = block.data_hash == data_hash
        return {
            "verified":      match,
            "on_chain_hash": block.data_hash,
            "provided_hash": data_hash,
            "block_index":   block.index,
            "block_hash":    block.block_hash,
            "timestamp":     block.timestamp,
            "message":       "✅ Integrity verified — data matches blockchain record"
                             if match else
                             "🚨 TAMPERED — data hash does not match blockchain record",
        }

    def verify_chain(self) -> dict:
        """
        Full chain integrity check — validates every block's hash-link.

        Returns
        -------
        dict with keys:
          valid         : bool
          length        : int
          broken_at     : int | None  (index of first invalid block)
          message       : str
        """
        for i, block in enumerate(self._chain):
            if not block.is_valid(self._difficulty):
                return {
                    "valid": False,
                    "length": len(self._chain),
                    "broken_at": i,
                    "message": f"Block #{i} has been tampered with (hash mismatch)",
                }
            if i > 0 and block.previous_hash != self._chain[i - 1].block_hash:
                return {
                    "valid": False,
                    "length": len(self._chain),
                    "broken_at": i,
                    "message": f"Chain broken at block #{i} (previous_hash mismatch)",
                }
        return {
            "valid": True,
            "length": len(self._chain),
            "broken_at": None,
            "message": f"✅ Chain intact — {len(self._chain)} blocks verified",
        }

    def get_recent_blocks(self, n: int = 20) -> list[dict]:
        """Return the last n blocks as dicts (newest first)."""
        return [b.to_dict() for b in reversed(self._chain[-n:])]

    def get_stats(self) -> dict:
        integrity = self.verify_chain()
        type_counts: dict[str, int] = {}
        for b in self._chain:
            type_counts[b.record_type] = type_counts.get(b.record_type, 0) + 1
        return {
            "length":        len(self._chain),
            "last_hash":     self._chain[-1].block_hash if self._chain else "",
            "integrity":     integrity["valid"],
            "integrity_msg": integrity["message"],
            "record_types":  type_counts,
            "difficulty":    self._difficulty,
        }

    def get_block_by_record(self, record_id: str) -> Optional[dict]:
        block = self._index.get(record_id)
        return block.to_dict() if block else None


# ── Singleton ─────────────────────────────────────────────────────────────────

_chain_instance: Optional[LocalChain] = None


def get_chain() -> LocalChain:
    """Return the module-level singleton LocalChain (lazy-initialised)."""
    global _chain_instance
    if _chain_instance is None:
        _chain_instance = LocalChain()
    return _chain_instance
