# blockchain package — tamper-evident evidence ledger
from blockchain.evidence_chain import get_evidence_chain, EvidenceChain
from blockchain.local_chain import get_chain, LocalChain
from blockchain.hasher import hash_alert, hash_event, hash_file, hash_audit_action

__all__ = [
    "get_evidence_chain", "EvidenceChain",
    "get_chain", "LocalChain",
    "hash_alert", "hash_event", "hash_file", "hash_audit_action",
]
