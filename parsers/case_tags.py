"""
Phase 5B.6: tags on records, stored in the case file.

A tag says what the examiner decided about a record: relied upon, of interest, complainant, privileged, excluded,
or a label of their own. The tool never applies a tag by itself.

Records are numbered by the store, and the numbers change when an evidence item is processed again. A tag therefore
also keeps the record's provenance line (source file, offset, state). After a re-process, ``reattach`` moves each tag
to the new record that has the same provenance, but only when exactly one record matches. A tag that cannot be placed
is kept and marked ``detached`` so that nothing the examiner decided is lost silently.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

BUILTIN_TAGS = {
    "relied_upon": "Relied upon: the examiner relies on this record in the report.",
    "of_interest": "Of interest: to be looked at again; no decision yet.",
    "complainant": "Belongs to the complainant or victim; left out of lists of accounts of interest.",
    "privileged": "Privileged or otherwise protected; not to be shown to the reviewer.",
    "excluded": "Excluded: not relevant to the case.",
}
MAX_TAG_CHARS = 40
MAX_BATCH = 5000
SUMMARY_FIELDS = ("Message_Body", "Content_Snippet", "Text", "Counterparty", "Peer", "Place_Name", "Contact_Name",
                  "Counterparty_Nick", "Order_Number", "Transaction_ID")


class TagError(ValueError):
    """The request cannot be carried out; the message says why."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Tag TEXT NOT NULL,
    Tbl TEXT NOT NULL,
    Record_Id INTEGER,
    Evidence_Item TEXT,
    Provenance TEXT,
    Summary TEXT,
    Note TEXT,
    Tagged_At_UTC TEXT NOT NULL,
    Detached INTEGER NOT NULL DEFAULT 0,
    UNIQUE(Tag, Tbl, Record_Id)
);
CREATE INDEX IF NOT EXISTS idx_tags_rec ON tags(Tbl, Record_Id);
CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(Tag, Detached);
"""


def normalise_tag(tag: str) -> str:
    t = " ".join(str(tag or "").split()).lower().replace(" ", "_")
    if not t:
        raise TagError("The tag is empty.")
    if len(t) > MAX_TAG_CHARS:
        raise TagError(f"The tag is longer than {MAX_TAG_CHARS} characters.")
    return t


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summary(row: sqlite3.Row) -> str:
    keys = row.keys()
    for f in SUMMARY_FIELDS:
        if f in keys and row[f] not in (None, ""):
            return str(row[f])[:200]
    return ""


def _checked_table(table: str, allowed: Iterable[str]) -> str:
    t = str(table).lower().strip()
    if t not in set(allowed) or t == "vfs_files":
        raise TagError(f"Records of {table!r} cannot be tagged.")
    return t


def apply_tag(conn: sqlite3.Connection, tag: str, records: Sequence[Tuple[str, int]], allowed: Iterable[str],
              note: str = "") -> Dict[str, Any]:
    tag = normalise_tag(tag)
    if not records:
        raise TagError("No records were given.")
    if len(records) > MAX_BATCH:
        raise TagError(f"At most {MAX_BATCH} records can be tagged in one request.")
    allowed = list(allowed)
    checked = [(_checked_table(t, allowed), int(i)) for t, i in records]      # refuse the whole request before changing anything
    applied, already, missing = 0, 0, []
    now = _now()
    for t, rid in checked:
        row = conn.execute(f'SELECT * FROM "{t}" WHERE id = ?', (rid,)).fetchone()
        if row is None:
            missing.append({"table": t, "id": rid})
            continue
        keys = row.keys()
        cur = conn.execute(
            "INSERT OR IGNORE INTO tags(Tag, Tbl, Record_Id, Evidence_Item, Provenance, Summary, Note, Tagged_At_UTC) VALUES (?,?,?,?,?,?,?,?)",
            (tag, t, rid, row["Evidence_Item"] if "Evidence_Item" in keys else None,
             row["Forensic_Provenance"] if "Forensic_Provenance" in keys else None, _summary(row), (note or "")[:2000], now))
        if cur.rowcount:
            applied += 1
        else:
            already += 1
    conn.commit()
    return {"tag": tag, "applied": applied, "already_tagged": already, "missing": missing}


def remove_tag(conn: sqlite3.Connection, tag: str, records: Sequence[Tuple[str, int]]) -> Dict[str, Any]:
    tag = normalise_tag(tag)
    removed = 0
    for table, rid in records:
        removed += conn.execute("DELETE FROM tags WHERE Tag = ? AND Tbl = ? AND Record_Id = ?",
                                (tag, str(table).lower().strip(), int(rid))).rowcount
    conn.commit()
    return {"tag": tag, "removed": removed}


def list_tags(conn: sqlite3.Connection, evidence_item: Optional[str] = None) -> Dict[str, Any]:
    where, params = "", ()
    if evidence_item:
        where, params = " WHERE Evidence_Item = ?", (evidence_item,)
    counts: Dict[str, Dict[str, Any]] = {
        k: {"tag": k, "builtin": True, "meaning": v, "count": 0, "detached": 0, "by_table": {}} for k, v in BUILTIN_TAGS.items()}
    for tag, tbl, det, n in conn.execute(f"SELECT Tag, Tbl, Detached, COUNT(*) FROM tags{where} GROUP BY Tag, Tbl, Detached", params):
        e = counts.setdefault(tag, {"tag": tag, "builtin": False, "meaning": None, "count": 0, "detached": 0, "by_table": {}})
        e["count"] += n
        if det:
            e["detached"] += n
        e["by_table"][tbl] = e["by_table"].get(tbl, 0) + n
    return {"tags": list(counts.values()), "detached_total": sum(v["detached"] for v in counts.values())}


def tags_for(conn: sqlite3.Connection, table: str, ids: Sequence[int]) -> Dict[int, List[str]]:
    """The tags on each of the given records of one table (detached tags are not included)."""
    out: Dict[int, List[str]] = {}
    ids = [int(i) for i in ids if i is not None]
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        q = ",".join("?" * len(part))
        for rid, tag in conn.execute(
                f"SELECT Record_Id, Tag FROM tags WHERE Tbl = ? AND Detached = 0 AND Record_Id IN ({q}) ORDER BY Tag", [table] + part):
            out.setdefault(rid, []).append(tag)
    return out


def tagged_records(conn: sqlite3.Connection, tag: str, allowed: Iterable[str], tables: Optional[Sequence[str]] = None,
                   evidence_item: Optional[str] = None, include_detached: bool = True,
                   limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    tag = normalise_tag(tag)
    where, params = ["Tag = ?"], [tag]
    if tables:
        asked = [_checked_table(t, allowed) for t in tables]
        where.append(f"Tbl IN ({','.join('?' * len(asked))})")
        params += asked
    if evidence_item:
        where.append("Evidence_Item = ?")
        params.append(evidence_item)
    if not include_detached:
        where.append("Detached = 0")
    w = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM tags WHERE {w}", params).fetchone()[0]
    rows = conn.execute(f"SELECT * FROM tags WHERE {w} ORDER BY Tagged_At_UTC, id LIMIT ? OFFSET ?",
                        params + [max(1, min(int(limit), 500)), max(0, int(offset))]).fetchall()
    return {"tag": tag, "total": total, "records": [
        {"table": r["Tbl"], "id": r["Record_Id"], "evidence_item": r["Evidence_Item"], "summary": r["Summary"],
         "provenance": r["Provenance"], "note": r["Note"], "tagged_at_utc": r["Tagged_At_UTC"], "detached": bool(r["Detached"])}
        for r in rows]}


def snapshot_item(conn: sqlite3.Connection, evidence_item: str) -> int:
    """Before an item is processed again its records are replaced: set its tags aside. Returns how many."""
    n = conn.execute("UPDATE tags SET Record_Id = NULL, Detached = 1 WHERE Evidence_Item = ? AND Detached = 0",
                     (evidence_item,)).rowcount
    conn.commit()
    return n


def reattach(conn: sqlite3.Connection, evidence_item: str, allowed: Iterable[str]) -> Dict[str, int]:
    """After an item is processed again: put each set-aside tag on the one new record with the same provenance."""
    allowed = set(allowed)
    placed = 0
    rows = conn.execute("SELECT id, Tag, Tbl, Provenance FROM tags WHERE Evidence_Item = ? AND Detached = 1", (evidence_item,)).fetchall()
    for tid, tag, tbl, prov in rows:
        if tbl not in allowed or not prov:
            continue
        found = conn.execute(f'SELECT id FROM "{tbl}" WHERE Evidence_Item = ? AND Forensic_Provenance = ? LIMIT 2',
                             (evidence_item, prov)).fetchall()
        if len(found) != 1:
            continue
        if conn.execute("SELECT 1 FROM tags WHERE Tag = ? AND Tbl = ? AND Record_Id = ?", (tag, tbl, found[0][0])).fetchone():
            continue
        conn.execute("UPDATE tags SET Record_Id = ?, Detached = 0 WHERE id = ?", (found[0][0], tid))
        placed += 1
    conn.commit()
    left = conn.execute("SELECT COUNT(*) FROM tags WHERE Evidence_Item = ? AND Detached = 1", (evidence_item,)).fetchone()[0]
    return {"reattached": placed, "detached": left}
