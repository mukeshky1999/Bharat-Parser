"""
Saved filters: a named set of filter choices for one screen, kept in the case file.

A filter is only the examiner's own choices (which direction, which app, which text). It holds no evidence. It is kept
in the case, not in the browser, because the text typed into a filter can be a name or a number from the evidence.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List

SCOPES = frozenset({
    "upi_ledger", "calls", "search", "timeline", "crypto_custodial", "crypto_p2p", "crypto_bridge", "crypto_addresses",
})
MAX_PER_SCOPE = 100
MAX_NAME = 60
MAX_STATE_BYTES = 4096
MAX_VALUE_CHARS = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS saved_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Scope TEXT NOT NULL,
    Name TEXT NOT NULL,
    State TEXT NOT NULL,
    Saved_At_Utc TEXT NOT NULL,
    UNIQUE (Scope, Name)
);
"""


class FilterError(ValueError):
    """The filter was not saved; the message says why."""


def _clean_state(state: Any) -> Dict[str, Any]:
    if not isinstance(state, dict) or not state:
        raise FilterError("A filter needs at least one choice.")
    out: Dict[str, Any] = {}
    for k, v in state.items():
        key = str(k)[:40]
        if isinstance(v, bool) or isinstance(v, (int, float)) or v is None:
            out[key] = v
        elif isinstance(v, str):
            out[key] = v[:MAX_VALUE_CHARS]
        else:
            raise FilterError(f"The choice '{key}' is not a plain value.")
    if len(json.dumps(out)) > MAX_STATE_BYTES:
        raise FilterError("The filter is too large.")
    return out


def list_filters(conn: sqlite3.Connection, scope: str) -> List[Dict[str, Any]]:
    if scope not in SCOPES:
        raise FilterError("Unknown screen.")
    return [{"name": r[0], "state": json.loads(r[1]), "saved_at_utc": r[2]}
            for r in conn.execute("SELECT Name, State, Saved_At_Utc FROM saved_filters WHERE Scope = ? ORDER BY Name COLLATE NOCASE", (scope,))]


def save_filter(conn: sqlite3.Connection, scope: str, name: str, state: Any) -> Dict[str, Any]:
    if scope not in SCOPES:
        raise FilterError("Unknown screen.")
    nm = " ".join(str(name or "").split())
    if not nm or len(nm) > MAX_NAME:
        raise FilterError(f"Give the filter a name of 1 to {MAX_NAME} characters.")
    clean = _clean_state(state)
    exists = conn.execute("SELECT 1 FROM saved_filters WHERE Scope = ? AND Name = ?", (scope, nm)).fetchone()
    if not exists and conn.execute("SELECT COUNT(*) FROM saved_filters WHERE Scope = ?", (scope,)).fetchone()[0] >= MAX_PER_SCOPE:
        raise FilterError(f"At most {MAX_PER_SCOPE} saved filters per screen.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO saved_filters (Scope, Name, State, Saved_At_Utc) VALUES (?,?,?,?) "
        "ON CONFLICT(Scope, Name) DO UPDATE SET State = excluded.State, Saved_At_Utc = excluded.Saved_At_Utc",
        (scope, nm, json.dumps(clean, sort_keys=True), now))
    conn.commit()
    return {"name": nm, "replaced": bool(exists)}


def remove_filter(conn: sqlite3.Connection, scope: str, name: str) -> Dict[str, Any]:
    if scope not in SCOPES:
        raise FilterError("Unknown screen.")
    cur = conn.execute("DELETE FROM saved_filters WHERE Scope = ? AND Name = ?", (scope, name))
    conn.commit()
    return {"removed": cur.rowcount}
