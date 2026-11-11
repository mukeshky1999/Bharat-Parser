"""
Tamper-Evident Merkle Chain-of-Custody & Examiner Audit Ledger (Sub-Engine 8.3C).
Enforces append-only cryptographic chaining H_n = SHA256(H_{n-1} | n | timestamp | event | payload).
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Optional

from src.legal_and_bsa.models import ChainOfCustodyEntry


class ChainOfCustodyTamperException(Exception):
    """Raised when cryptographic verification detects tampering, omission, or alteration in the audit ledger."""


class MerkleChainOfCustodyLedger:
    """Maintains an immutable, hash-chained append-only ledger of forensic operations and examiner actions."""

    def __init__(self):
        self.genesis_hash_hex: Optional[str] = None
        self.entries: list[ChainOfCustodyEntry] = []

    def initialize_chain(self, case_uuid: str, master_sha256: str) -> str:
        """Computes the Genesis Anchor H_0 binding case identity and primary acquisition image hash."""
        genesis_payload = (
            b"FORENSIC_GENESIS_V1:"
            + case_uuid.encode("utf-8")
            + master_sha256.lower().encode("utf-8")
        )
        self.genesis_hash_hex = hashlib.sha256(genesis_payload).hexdigest().lower()
        return self.genesis_hash_hex

    def append_entry(
        self,
        actor: str,
        event_action_type: str,
        payload_dict: dict[str, Any],
        custom_timestamp_ns: Optional[int] = None,
    ) -> ChainOfCustodyEntry:
        """Computes H_n and appends an immutable audit event to the hash chain."""
        if not self.genesis_hash_hex:
            raise RuntimeError("Chain not initialized: call initialize_chain() first")

        seq_no = len(self.entries) + 1
        prev_hash = (
            self.entries[-1].current_entry_hash_hex
            if self.entries
            else self.genesis_hash_hex
        )

        now_utc = datetime.now(timezone.utc)
        ts_ns = custom_timestamp_ns or int(now_utc.timestamp() * 1_000_000_000)
        ts_ist_iso = now_utc.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        canonical_json = json.dumps(payload_dict, sort_keys=True)

        # H_n = SHA256(H_{n-1} | n | timestamp_utc_ns | event_action_type | canonical_payload_json)
        chain_string = f"{prev_hash}|{seq_no}|{ts_ns}|{event_action_type}|{canonical_json}"
        curr_hash = hashlib.sha256(chain_string.encode("utf-8")).hexdigest().lower()

        entry = ChainOfCustodyEntry(
            seq_no=seq_no,
            timestamp_utc_ns=ts_ns,
            timestamp_ist_iso=ts_ist_iso,
            actor_or_subsystem=actor,
            event_action_type=event_action_type,
            canonical_payload_json=canonical_json,
            previous_entry_hash_hex=prev_hash,
            current_entry_hash_hex=curr_hash,
        )
        self.entries.append(entry)
        return entry

    def verify_chain_integrity(self) -> bool:
        """Verifies the unbroken cryptographic continuity of all entries from Genesis H_0 to the present."""
        if not self.genesis_hash_hex:
            raise ChainOfCustodyTamperException("Genesis anchor missing")

        for idx, entry in enumerate(self.entries):
            expected_prev = (
                self.genesis_hash_hex
                if idx == 0
                else self.entries[idx - 1].current_entry_hash_hex
            )

            if entry.previous_entry_hash_hex != expected_prev:
                raise ChainOfCustodyTamperException(
                    f"Chain linkage broken at sequence {entry.seq_no}: previous hash mismatch "
                    f"(expected {expected_prev}, recorded {entry.previous_entry_hash_hex})"
                )

            chain_string = (
                f"{entry.previous_entry_hash_hex}|{entry.seq_no}|"
                f"{entry.timestamp_utc_ns}|{entry.event_action_type}|{entry.canonical_payload_json}"
            )
            recomputed_curr = hashlib.sha256(chain_string.encode("utf-8")).hexdigest().lower()

            if entry.current_entry_hash_hex != recomputed_curr:
                raise ChainOfCustodyTamperException(
                    f"Cryptographic hash mismatch at sequence {entry.seq_no}: "
                    f"computed {recomputed_curr}, recorded {entry.current_entry_hash_hex}"
                )

        return True
