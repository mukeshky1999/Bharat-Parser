"""
Phase 5B.9: the key broker's facts.

The examiner supplies keys for encrypted databases. This module only describes them and reports what the case
recorded about key use. It never stores a key, never returns one, never generates or guesses one.

* ``inspect_keys``: for each supplied name, the readings the ingest would try (raw bytes, hex, base64, passphrase)
  and the 8-digit fingerprint of each reading, which is what the audit log records. A value with no usable reading
  is said to have none.
* ``keys_needed``: the files the case could not open for want of a key, from the coverage report.
* ``key_events``: what the audit log says about keys (names and fingerprints only).
"""
from __future__ import annotations

from typing import Any, Dict, List

from parsers import encrypted_db

MAX_KEYS = 50
MAX_VALUE_CHARS = 4096


class KeyBrokerError(ValueError):
    """The request cannot be carried out; the message says why."""


def inspect_keys(keys: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(keys, dict) or not keys:
        raise KeyBrokerError("No keys were given.")
    if len(keys) > MAX_KEYS:
        raise KeyBrokerError(f"At most {MAX_KEYS} keys can be checked at once.")
    out: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}                      # fingerprint -> first name that produced it
    for raw_name, value in keys.items():
        name = " ".join(str(raw_name).split())[:80]
        text = "" if value is None else str(value)
        row: Dict[str, Any] = {"name": name, "readings": [], "problems": []}
        if not name:
            row["problems"].append("The key has no name. A name is how the audit log refers to it.")
        if not text.strip():
            row["problems"].append("The value is empty.")
        elif len(text) > MAX_VALUE_CHARS:
            row["problems"].append(f"The value is longer than {MAX_VALUE_CHARS} characters.")
        else:
            for how, material in encrypted_db.normalise_key(text):
                fp = encrypted_db.key_fingerprint(material)
                row["readings"].append({"how": how, "fingerprint": fp})
                if fp in seen and seen[fp] != name:
                    row["problems"].append(f"Reading '{how}' is the same key material as '{seen[fp]}'.")
                seen.setdefault(fp, name)
            if not row["readings"]:
                row["problems"].append("No reading is possible: it is not 64 or 96 hex digits, not base64 of 32 or 48 bytes, "
                                       "and not a passphrase of 4 to 256 characters.")
        row["usable"] = bool(row["readings"])
        out.append(row)
    return out


def keys_needed(coverage_rows: List[Dict[str, Any]], items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Files that could not be opened without a key, grouped by evidence item, with the source to process again."""
    by_item: Dict[str, Dict[str, Any]] = {}
    for r in coverage_rows:
        if r.get("Outcome") not in ("ENCRYPTED_NO_KEY",):
            continue
        item = r.get("Evidence_Item") or ""
        g = by_item.setdefault(item, {"evidence_item": item, "files": []})
        g["files"].append({"file": r.get("File"), "size_bytes": r.get("Size_Bytes"), "reason": r.get("Reason") or None})
    meta = {i.get("item_id"): i for i in items or []}
    for item, g in by_item.items():
        m = meta.get(item) or {}
        g["label"] = m.get("label") or None
        g["source_path"] = m.get("source_path") or None
    return list(by_item.values())


def key_events(audit_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """keys_available / key_used entries of the audit log. Key material is never in them."""
    out = []
    for e in audit_entries or []:
        if e.get("action") in ("keys_available", "key_used"):
            out.append({"seq": e.get("seq"), "ts_utc": e.get("ts_utc"), "action": e["action"], "details": e.get("payload") or {}})
    return out
