"""
Phase 5B.7: one timeline over every table that has a time.

What counts as a place on the timeline
--------------------------------------
fixed       the record has a Timestamp_IST that the source fixed to an instant (an epoch value, or a clock with its
            offset). These are ordered by that instant. The UTC value and the basis are shown when they were recorded.
clock_only  the record has only a local clock reading (for example a payment time with no zone). The zone is not
            recorded, so the tool does not know where the event falls against the others and does not place it among
            them. They are counted, and listed on request.
no_time     the record has no usable time. Counted, listed on request.

Events of different devices are ordered by their recorded instants as they are; a device clock that was wrong is not
corrected here. A timeline never changes the case store.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Sequence

GROUPS = ("fixed", "clock_only", "no_time")
BUCKETS = {"day": 10, "hour": 13}
MAX_BUCKETS = 5000


class TimelineError(ValueError):
    """The request cannot be carried out; the message says why."""


def _cat(*parts: str) -> str:
    """SQL text joining the non-empty columns with a space."""
    return "TRIM(" + " || ' ' || ".join(f"COALESCE({p}, '')" for p in parts) + ")"


# kind: label shown; summary: SQL; app: SQL; utc / ist / clock / basis: SQL (NULL when the table has none)
SPECS: Dict[str, Dict[str, str]] = {
    "chats": {"kind": "Message", "app": "Application", "utc": "Timestamp_UTC", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
              "summary": _cat("Direction", "Sender_Name", "'->'", "Recipient_Name", "':'", "Message_Body")},
    "transactions": {"kind": "Payment", "app": "Application", "utc": "Timestamp_UTC", "ist": "Timestamp_IST", "clock": "Date",
                     "basis": "Timestamp_Basis", "summary": _cat("Direction", "Amount", "Counterparty", "Status")},
    "calls": {"kind": "Call", "app": "Application", "utc": "Timestamp_UTC", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
              "summary": _cat("Call_Type", "Direction", "Peer", "Call_Result", "CAST(Duration_Sec AS TEXT)")},
    "locations": {"kind": "Location", "app": "Application", "utc": "Timestamp_UTC", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
                  "summary": _cat("Place_Name", "Geo_Coordinates")},
    "os_spillover": {"kind": "Device trace", "app": "Package_Name", "utc": "NULL", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
                     "summary": _cat("Vector_Type", "Content_Snippet")},
    "notifications": {"kind": "Notification", "app": "Package_Name", "utc": "NULL", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
                      "summary": _cat("Title", "Text")},
    "bank_alerts": {"kind": "Bank alert", "app": "Institution", "utc": "Received_UTC", "ist": "Received_IST", "clock": "NULL", "basis": "NULL",
                    "summary": _cat("Category", "Amount", "Counterparty", "Account_Masked")},
    "p2p_orders": {"kind": "P2P order", "app": "Platform", "utc": "NULL", "ist": "Timestamp_IST", "clock": "NULL", "basis": "NULL",
                   "summary": _cat("Trade_Type", "Fiat_Amount", "Fiat_Currency", "Counterparty_Nick", "Order_Status")},
}

_VALID = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][ T][0-9][0-9]:[0-9][0-9]:[0-9][0-9]*"


def _ist_key(expr: str) -> str:
    return f"substr(replace({expr}, 'T', ' '), 1, 19)"


def _select(table: str, spec: Dict[str, str], group: str, frm: Optional[str], to: Optional[str],
            evidence_item: Optional[str], application: Optional[str], tag: Optional[str]) -> tuple:
    ist, clock = spec["ist"], spec["clock"]
    fixed = f"COALESCE({ist} GLOB '{_VALID}', 0)"
    has_clock = f"COALESCE({clock} GLOB '{_VALID}', 0)" if clock != "NULL" else "0"
    where, params = [], []
    if group == "fixed":
        where.append(fixed)
        if frm:
            where.append(f"{_ist_key(ist)} >= ?")
            params.append(frm)
        if to:
            where.append(f"{_ist_key(ist)} <= ?")
            params.append(to)
    elif group == "clock_only":
        where.append(f"NOT {fixed} AND {has_clock}")
    else:
        where.append(f"NOT {fixed} AND NOT {has_clock}")
    if evidence_item:
        where.append("Evidence_Item = ?")
        params.append(evidence_item)
    if application:
        where.append(f"{spec['app']} = ?")
        params.append(application)
    if tag:
        where.append("id IN (SELECT Record_Id FROM tags WHERE Tbl = ? AND Tag = ? AND Detached = 0)")
        params += [table, tag]
    sql = (f"SELECT '{table}' AS tbl, id, Evidence_Item AS evidence_item, {spec['app']} AS application, '{spec['kind']}' AS kind, "
           f"{spec['summary']} AS summary, {spec['utc']} AS utc, {ist} AS ist, {clock} AS local_clock, {spec['basis']} AS basis, "
           f"{_ist_key(ist)} AS sort_key, Forensic_Provenance AS provenance, Decoded_By AS decoded_by "
           f"FROM \"{table}\" WHERE " + " AND ".join(where))
    return sql, params


def timeline(conn: sqlite3.Connection, tables: Optional[Sequence[str]] = None, group: str = "fixed",
             frm: Optional[str] = None, to: Optional[str] = None, evidence_item: Optional[str] = None,
             application: Optional[str] = None, tag: Optional[str] = None, bucket: Optional[str] = None,
             limit: int = 100, offset: int = 0, descending: bool = False) -> Dict[str, Any]:
    if group not in GROUPS:
        raise TimelineError(f"Unknown group {group!r}. Use one of: {', '.join(GROUPS)}.")
    if bucket is not None and bucket not in BUCKETS:
        raise TimelineError(f"Unknown bucket {bucket!r}. Use one of: {', '.join(BUCKETS)}.")
    for label, v in (("from", frm), ("to", to)):
        if v and not _looks_like_time(v):
            raise TimelineError(f"'{label}' must look like 2026-02-01 or 2026-02-01 09:30:00 (Indian Standard Time), not {v!r}.")
    if frm and to and _bound(frm, False) > _bound(to, True):      # compared in one form: "T" and a space sort differently
        raise TimelineError("'from' is after 'to'.")
    tag_name = None
    if tag:
        from parsers.case_tags import normalise_tag, TagError
        try:
            tag_name = normalise_tag(tag)
        except TagError as exc:
            raise TimelineError(str(exc))
    present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    wanted = [t for t in SPECS if t in present]
    if tables:
        asked = [t.lower().strip() for t in tables]
        unknown = [t for t in asked if t not in SPECS]
        if unknown:
            raise TimelineError(f"Not a table with a time: {', '.join(unknown)}. Use: {', '.join(SPECS)}.")
        wanted = [t for t in wanted if t in asked]
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    # a day-only bound covers the whole day
    f_key = _bound(frm, False)
    t_key = _bound(to, True)

    def union(g: str) -> tuple:
        parts, params = [], []
        for t in wanted:
            s, p = _select(t, SPECS[t], g, f_key, t_key, evidence_item, application, tag_name)
            parts.append(s)
            params += p
        return " UNION ALL ".join(parts), params

    # how many records fall in each group (the filters of table, device, application and tag apply; the time range only to "fixed")
    counts = {}
    for g in GROUPS:
        if not wanted:
            counts[g] = 0
            continue
        sql, params = union(g)
        counts[g] = conn.execute(f"SELECT COUNT(*) FROM ({sql})", params).fetchone()[0]

    result: Dict[str, Any] = {
        "group": group, "from": frm, "to": to, "counts": counts, "total": counts[group], "offset": offset, "limit": limit,
        "ordering": ("by the recorded instant (Timestamp_IST); equal instants by table then id" if group == "fixed"
                     else "not placed on the timeline: the source fixes no instant" if group == "clock_only" else "no usable time"),
        "note": ("Records with only a local clock reading and no zone are not placed here (see counts.clock_only). "
                 "A device clock that was wrong is not corrected."),
    }
    if not wanted:
        result.update(events=[], buckets=None, time_basis={})
        return result
    sql, params = union(group)
    order = "DESC" if descending else "ASC"
    key = "sort_key" if group == "fixed" else "local_clock" if group == "clock_only" else "id"
    cur = conn.execute(f"SELECT * FROM ({sql}) ORDER BY {key} {order}, tbl, id LIMIT ? OFFSET ?", params + [limit, offset])
    names = [d[0] for d in cur.description]
    events = [dict(zip(names, r)) for r in cur.fetchall()]
    for e in events:
        e["summary"] = (e["summary"] or "")[:300]
        e["time_basis"] = e.pop("basis") or ("RECORDED_UTC_AND_IST" if e["utc"] not in (None, "") else "RECORDED_IST")
        e.pop("sort_key", None)
    if events and "tags" in present:
        from parsers.case_tags import tags_for
        for tb in {e["tbl"] for e in events}:
            found = tags_for(conn, tb, [e["id"] for e in events if e["tbl"] == tb])
            for e in events:
                if e["tbl"] == tb:
                    e["tags"] = found.get(e["id"], [])
    result["events"] = events

    basis: Dict[str, int] = {}
    if group == "fixed":
        for b, n in conn.execute(
                f"SELECT COALESCE(basis, CASE WHEN NULLIF(utc, '') IS NOT NULL THEN 'RECORDED_UTC_AND_IST' ELSE 'RECORDED_IST' END), COUNT(*) "
                f"FROM ({sql}) GROUP BY 1", params):
            basis[b] = n
    result["time_basis"] = basis

    result["buckets"] = None
    if bucket and group == "fixed":
        n = BUCKETS[bucket]
        rows = conn.execute(f"SELECT substr(sort_key, 1, {n}) AS b, COUNT(*) FROM ({sql}) GROUP BY b ORDER BY b LIMIT ?",
                            params + [MAX_BUCKETS + 1]).fetchall()
        result["buckets"] = {"size": bucket, "truncated": len(rows) > MAX_BUCKETS,
                             "items": [{"start": b, "count": c} for b, c in rows[:MAX_BUCKETS]]}
    return result


def _looks_like_time(v: str) -> bool:
    import re
    return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?", v.strip()))


def _bound(v: Optional[str], upper: bool) -> Optional[str]:
    if not v:
        return None
    s = v.strip().replace("T", " ")
    if len(s) == 10:
        return s + (" 23:59:59" if upper else " 00:00:00")
    if len(s) == 16:
        return s + (":59" if upper else ":00")
    return s
