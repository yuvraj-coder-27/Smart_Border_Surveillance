// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title EvidenceLedger
 * @author Border Surveillance System — SIH 2026
 * @notice Immutable on-chain record of border surveillance evidence hashes.
 *
 * This contract is the Ethereum equivalent of blockchain/local_chain.py.
 * Deploy to a private Ganache instance or any EVM-compatible chain.
 *
 * How it works
 * ------------
 * 1. When a surveillance alert is created, the backend computes
 *    SHA-256(canonical_alert_json) and calls record().
 * 2. When an operator wants to verify an alert was not tampered with,
 *    they call verify() — returns true only if the hash still matches.
 * 3. All record() calls emit a Recorded event, giving a permanent
 *    transaction trail on the blockchain.
 *
 * Deploy with Web3.py + Ganache:
 *   pip install web3 py-solc-x
 *   python blockchain/deploy.py
 */
contract EvidenceLedger {

    // ── Data structures ───────────────────────────────────────────────────────

    struct LedgerRecord {
        string  recordId;    // e.g. "alert_42", "evidence_7", "audit_dismiss_42"
        string  dataHash;    // SHA-256 hex of the canonical record content
        uint256 timestamp;   // block.timestamp at time of recording
        string  recordType;  // "alert" | "evidence" | "audit"
        address recorder;    // who submitted the transaction
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    mapping(string => LedgerRecord) private _records;
    string[] private _recordIds;
    address public owner;

    // ── Events ────────────────────────────────────────────────────────────────

    event Recorded(
        string  indexed recordId,
        string          dataHash,
        string          recordType,
        uint256         timestamp,
        address indexed recorder
    );

    event TamperDetected(
        string  indexed recordId,
        string          storedHash,
        string          providedHash,
        uint256         checkedAt
    );

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /**
     * @notice Record a SHA-256 hash of a surveillance record on-chain.
     * @param recordId   Unique ID, e.g. "alert_42"
     * @param dataHash   SHA-256 hex string of the canonical record content
     * @param recordType One of "alert", "evidence", "audit"
     */
    function record(
        string calldata recordId,
        string calldata dataHash,
        string calldata recordType
    ) external {
        require(bytes(recordId).length > 0,   "recordId required");
        require(bytes(dataHash).length == 64, "dataHash must be 64-char SHA-256 hex");
        // Allow re-recording only if the slot is empty (first-write-wins)
        require(
            bytes(_records[recordId].recordId).length == 0,
            "Record already committed — first-write-wins"
        );

        _records[recordId] = LedgerRecord({
            recordId:   recordId,
            dataHash:   dataHash,
            timestamp:  block.timestamp,
            recordType: recordType,
            recorder:   msg.sender
        });
        _recordIds.push(recordId);

        emit Recorded(recordId, dataHash, recordType, block.timestamp, msg.sender);
    }

    // ── Read / Verify ─────────────────────────────────────────────────────────

    /**
     * @notice Verify that the provided hash matches the committed hash.
     * @param recordId   The record to check
     * @param dataHash   The current SHA-256 of the record (recomputed by caller)
     * @return           True if hashes match (not tampered), False otherwise
     */
    function verify(
        string calldata recordId,
        string calldata dataHash
    ) external returns (bool) {
        LedgerRecord storage r = _records[recordId];
        bool match = keccak256(bytes(r.dataHash)) == keccak256(bytes(dataHash));
        if (!match) {
            emit TamperDetected(recordId, r.dataHash, dataHash, block.timestamp);
        }
        return match;
    }

    /**
     * @notice Get the full record for a given recordId.
     */
    function getRecord(string calldata recordId)
        external
        view
        returns (
            string memory id,
            string memory dataHash,
            uint256 timestamp,
            string memory recordType,
            address recorder
        )
    {
        LedgerRecord storage r = _records[recordId];
        return (r.recordId, r.dataHash, r.timestamp, r.recordType, r.recorder);
    }

    /**
     * @notice Total number of records committed.
     */
    function getCount() external view returns (uint256) {
        return _recordIds.length;
    }

    /**
     * @notice Get the recordId at a given index (for enumeration).
     */
    function getRecordIdAt(uint256 index) external view returns (string memory) {
        require(index < _recordIds.length, "Index out of range");
        return _recordIds[index];
    }
}
