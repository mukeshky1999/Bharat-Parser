"""Append-only, hash-chained audit log for a case.

Every examiner or system action (case opened, evidence hashed, key supplied, record pinned, report generated)
is one line in a JSON-lines file. Each entry's hash covers the previous entry's hash, the sequence number,
the time, the actor, the action and the canonical payload:

    H_n = SHA256(H_{n-1} | seq | ts_ns | action | actor | canonical_payload_json)

Properties and limits (state these wherever the log is shown):
* Editing, reordering or deleting an entry in the middle breaks the chain and `verify()` reports where.
* Someone who can rewrite the whole file can recompute every hash. The chain therefore proves consistency, not
  authorship. Reports embed `head_hash`, so a reader who holds an earlier report can detect that entries were
  removed from the end afterwards.
* Time comes from the examiner's machine clock and is recorded as UTC plus IST derived from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

IST = timezone(timedelta(hours=5, minutes=30))
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditTamperError(Exception):
    """The audit log failed verification."""


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts_ns: int
    ts_utc: str
    ts_ist: str
    actor: str
    action: str
    payload_json: str
    prev_hash: str
    hash: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str
    error: str = ""


def canonical_json(payload: Dict[str, Any]) -> str:
    """Deterministic JSON. Raises TypeError on values that cannot be represented exactly (no silent str())."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(prev_hash: str, seq: int, ts_ns: int, action: str, actor: str, payload_json: str) -> str:
    text = f"{prev_hash}|{seq}|{ts_ns}|{action}|{actor}|{payload_json}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def genesis_hash(case_id: str) -> str:
    return hashlib.sha256(("AUDIT_GENESIS_V1:" + str(case_id)).encode("utf-8")).hexdigest()


def _stamp(ts_ns: int) -> tuple[str, str]:
    utc = datetime.fromtimestamp(ts_ns / 1_000_000_000, tz=timezone.utc)
    ist = utc.astimezone(IST)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), ist.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")


class AuditLedger:
    """A case's audit log. `path=None` keeps it in memory (tests); otherwise each entry is fsynced to the file."""

    def __init__(self, case_id: str, path: Optional[str] = None):
        if not str(case_id).strip():
            raise ValueError("case_id is required")
        self.case_id = str(case_id)
        self.path = path
        self._lock = threading.Lock()
        self.entries: List[AuditEntry] = []
        self._genesis = genesis_hash(self.case_id)
        if path and os.path.exists(path):
            self._load(path)

    # ------------------------------------------------------------------ reading
    def _load(self, path: str) -> None:
        loaded: List[AuditEntry] = []
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    loaded.append(AuditEntry(**json.loads(line)))
                except (ValueError, TypeError) as exc:
                    raise AuditTamperError(f"line {n} is not a valid audit entry: {exc}") from exc
        self.entries = loaded
        result = self.verify()
        if not result.ok:
            raise AuditTamperError(result.error)

    @property
    def head_hash(self) -> str:
        return self.entries[-1].hash if self.entries else self._genesis

    # ------------------------------------------------------------------ writing
    def append(self, actor: str, action: str, payload: Optional[Dict[str, Any]] = None,
               ts_ns: Optional[int] = None) -> AuditEntry:
        if not str(actor).strip() or not str(action).strip():
            raise ValueError("actor and action are required")
        payload_json = canonical_json(payload or {})
        with self._lock:
            seq = len(self.entries) + 1
            prev = self.head_hash
            if ts_ns is None:
                ts_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
            ts_utc, ts_ist = _stamp(ts_ns)
            entry = AuditEntry(
                seq=seq, ts_ns=ts_ns, ts_utc=ts_utc, ts_ist=ts_ist, actor=str(actor), action=str(action),
                payload_json=payload_json, prev_hash=prev,
                hash=_entry_hash(prev, seq, ts_ns, str(action), str(actor), payload_json),
            )
            if self.path:
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            self.entries.append(entry)
            return entry

    # ------------------------------------------------------------------ checking
    def verify(self) -> VerifyResult:
        prev = self._genesis
        for i, e in enumerate(self.entries, 1):
            if e.seq != i:
                return VerifyResult(False, len(self.entries), self.head_hash, f"sequence gap or reorder at entry {i} (found {e.seq})")
            if e.prev_hash != prev:
                return VerifyResult(False, len(self.entries), self.head_hash, f"chain broken at entry {e.seq}: previous hash does not match")
            if not _SHA256_RE.match(e.hash):
                return VerifyResult(False, len(self.entries), self.head_hash, f"entry {e.seq} has no valid hash")
            if e.hash != _entry_hash(e.prev_hash, e.seq, e.ts_ns, e.action, e.actor, e.payload_json):
                return VerifyResult(False, len(self.entries), self.head_hash, f"entry {e.seq} was altered: hash does not match its content")
            prev = e.hash
        return VerifyResult(True, len(self.entries), self.head_hash)

    def verify_against_head(self, recorded_head: str) -> VerifyResult:
        """Check that a head hash quoted by an earlier report is still part of this chain (detects tail removal)."""
        base = self.verify()
        if not base.ok:
            return base
        if recorded_head == self._genesis or any(e.hash == recorded_head for e in self.entries):
            return base
        return VerifyResult(False, base.entries, base.head_hash, "the head hash quoted by the report is not in this log")
