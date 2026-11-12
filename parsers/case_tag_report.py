"""
Phase 5B.6 follow-up: what the examiner's tags mean for the report, the facts annexure and the review package.

Rules (the tool supplies facts; the examiner decides):
* A record is listed in the report as relied upon only when it carries ``relied_upon`` and does not carry ``privileged``.
  Records tagged privileged are counted, never listed.
* Tags that could not be placed after the evidence was processed again (detached) are counted, never listed:
  without a record there is no way to tell whether another tag on it would have excluded it.
* The accounts-of-interest sheet is built from payment records tagged ``of_interest`` or ``relied_upon``. An account
  (VPA or account number) is left out when any payment record sharing it is tagged complainant, excluded or privileged;
  the sheet then lists it under "left out" with the reason. Nothing is inferred beyond an exact value match.
"""
from __future__ import annotations

import csv
import io
import re
import sqlite3
from typing import Any, Dict, Iterable, List, Tuple

from parsers import case_tags

LIST_CAP = 200
KEEP_OUT = ("privileged", "complainant", "excluded")
INCLUDE_TAGS = ("of_interest", "relied_upon")


def _has_tags(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tags'").fetchone() is not None


def tag_facts(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Tag counts plus the relied-upon records, as plain data for the report."""
    empty: Dict[str, Any] = {"available": False, "tags": [], "detached_total": 0, "relied_upon": [], "relied_upon_total": 0,
                             "relied_upon_withheld_privileged": 0, "relied_upon_detached": 0, "list_cap": LIST_CAP}
    if not _has_tags(conn):
        return empty
    summary = case_tags.list_tags(conn)
    privileged = {(t, r) for t, r in conn.execute("SELECT Tbl, Record_Id FROM tags WHERE Tag = 'privileged' AND Detached = 0")}
    # a privileged tag that lost its record still names the source location it was placed on: that location is withheld too
    privileged_prov = {(t, p) for t, p in conn.execute("SELECT Tbl, Provenance FROM tags WHERE Tag = 'privileged' AND Detached = 1")
                       if p}
    rows = conn.execute(
        "SELECT Tbl, Record_Id, Evidence_Item, Summary, Provenance, Note, Tagged_At_UTC FROM tags "
        "WHERE Tag = 'relied_upon' AND Detached = 0 ORDER BY Tagged_At_UTC, id").fetchall()
    listed, withheld = [], 0
    for tbl, rid, item, summ, prov, note, at in rows:
        if (tbl, rid) in privileged or (tbl, prov) in privileged_prov:
            withheld += 1
            continue
        listed.append({"table": tbl, "id": rid, "evidence_item": item, "summary": summ, "provenance": prov,
                       "note": note, "tagged_at_utc": at})
    detached = conn.execute("SELECT COUNT(*) FROM tags WHERE Tag = 'relied_upon' AND Detached = 1").fetchone()[0]
    return {"available": True, "tags": summary["tags"], "detached_total": summary["detached_total"],
            "relied_upon": listed[:LIST_CAP], "relied_upon_total": len(listed),
            "relied_upon_withheld_privileged": withheld, "relied_upon_detached": detached, "list_cap": LIST_CAP}


def _norm(v: Any) -> str:
    return str(v).strip().lower() if v not in (None, "") else ""


def accounts_of_interest(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Accounts (VPA / account number) from tagged payment records, with those left out and why."""
    if not _has_tags(conn):
        return {"accounts": [], "left_out": [], "keep_out_tags_not_traced": 0, "note": "No tags exist in this case."}
    marks: Dict[int, set] = {}
    for rid, tag in conn.execute("SELECT Record_Id, Tag FROM tags WHERE Tbl = 'transactions' AND Detached = 0"):
        marks.setdefault(rid, set()).add(tag)
    if not marks:
        return {"accounts": [], "left_out": [], "keep_out_tags_not_traced": 0, "note": "No payment records are tagged."}
    ids = list(marks)
    rows = []
    for i in range(0, len(ids), 500):           # SQLite limits the number of parameters in one statement
        part = ids[i:i + 500]
        rows += conn.execute("SELECT id, Counterparty, VPA, Account, Evidence_Item, Application FROM transactions WHERE id IN (%s)"
                             % ",".join("?" * len(part)), part).fetchall()
    # every identifier that appears on a payment record carrying a keep-out tag
    blocked: Dict[str, set] = {}
    untraced = 0
    # a keep-out tag set aside after processing again has no record id, but it kept the source location: every payment
    # record at that location is treated as carrying it. If no record is found there, the tag cannot be traced to an account.
    for tag, prov in conn.execute("SELECT Tag, Provenance FROM tags WHERE Tbl = 'transactions' AND Detached = 1 AND Tag IN (%s)"
                                  % ",".join("?" * len(KEEP_OUT)), list(KEEP_OUT)).fetchall():
        found = conn.execute("SELECT VPA, Account FROM transactions WHERE Forensic_Provenance = ?", (prov,)).fetchall() if prov else []
        if not found:
            untraced += 1
        for r in found:
            for kind, val in (("vpa", _norm(r["VPA"])), ("account", _norm(r["Account"]))):
                if val:
                    blocked.setdefault(kind + ":" + val, set()).add(tag + " (tag set aside)")
    for r in rows:
        why = marks[r["id"]] & set(KEEP_OUT)
        if not why:
            continue
        for kind, val in (("vpa", _norm(r["VPA"])), ("account", _norm(r["Account"]))):
            if val:
                blocked.setdefault(kind + ":" + val, set()).update(why)
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rows:
        if not (marks[r["id"]] & set(INCLUDE_TAGS)):
            continue
        vpa, acc = _norm(r["VPA"]), _norm(r["Account"])
        if not vpa and not acc:
            continue                      # nothing to list: a name alone is not an account
        g = groups.setdefault((vpa, acc), {"vpa": r["VPA"] or "", "account": r["Account"] or "", "names": set(), "records": [],
                                           "evidence_items": set(), "applications": set(), "tags": set()})
        if r["Counterparty"]:
            g["names"].add(r["Counterparty"])
        g["records"].append(r["id"])
        g["evidence_items"].add(r["Evidence_Item"] or "")
        g["applications"].add(r["Application"] or "")
        g["tags"] |= marks[r["id"]] & set(INCLUDE_TAGS)
    accounts, left_out = [], []
    for (vpa, acc), g in sorted(groups.items()):
        why: set = set()
        if vpa:
            why |= blocked.get("vpa:" + vpa, set())
        if acc:
            why |= blocked.get("account:" + acc, set())
        row = {"vpa": g["vpa"], "account": g["account"], "names_as_recorded": "; ".join(sorted(g["names"])),
               "tagged_records": len(g["records"]), "record_ids": ",".join(str(i) for i in sorted(g["records"])),
               "evidence_items": ";".join(sorted(x for x in g["evidence_items"] if x)),
               "applications": ";".join(sorted(x for x in g["applications"] if x)), "tags": ";".join(sorted(g["tags"]))}
        if why:
            row["left_out_because"] = ";".join(sorted(why))
            left_out.append(row)
        else:
            accounts.append(row)
    return {"accounts": accounts, "left_out": left_out, "keep_out_tags_not_traced": untraced,
            "note": ("%d complainant/excluded/privileged tag(s) were set aside by processing again and could not be traced to an "
                     "account; check them by hand before using this sheet. " % untraced if untraced else "") + "Built from payment records tagged of_interest or relied_upon. Accounts that also appear on a record tagged "
                    "complainant, excluded or privileged are listed apart. Matching is by exact VPA or account number only."}


def _cell(v: Any) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


_COLS = ["vpa", "account", "names_as_recorded", "tagged_records", "record_ids", "evidence_items", "applications", "tags"]


def accounts_csv(data: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["section"] + _COLS + ["left_out_because"])
    for r in data["accounts"]:
        w.writerow(["account of interest"] + [_cell(r[c]) for c in _COLS] + [""])
    for r in data["left_out"]:
        w.writerow(["left out"] + [_cell(r[c]) for c in _COLS] + [_cell(r["left_out_because"])])
    return buf.getvalue()


_COMPANION = re.compile(r"-(wal|shm|journal)$", re.I)


def _file_names_in(prov: str) -> set:
    """The file names a provenance line names: the path before the first ' :: ', and any 'In=<file> frame n' part.
    Journal / WAL / SHM companions count as the database they belong to."""
    names = set()
    path_part = prov.split(" :: ", 1)[0]
    cands = [path_part] + re.findall(r"In=(\S+)", prov)
    for c in cands:
        base = c.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
        if base:
            names.add(_COMPANION.sub("", base))
    return names


def files_with_keep_out_records(conn: sqlite3.Connection, file_names: Iterable[str]) -> Dict[str, Dict[str, int]]:
    """For each file name, how many records tagged privileged / complainant / excluded name that file in their provenance.

    A tag set aside after processing again is counted too (it still holds its provenance). The match is the file's whole
    name, as a path component of the stored provenance line (a -wal / -shm / -journal file counts as its database);
    a file whose name is not there matches nothing.
    """
    out: Dict[str, Dict[str, int]] = {}
    if not _has_tags(conn):
        return out
    rows = conn.execute(f"SELECT Tag, Provenance FROM tags WHERE Tag IN ({','.join('?' * len(KEEP_OUT))})",
                        list(KEEP_OUT)).fetchall()
    parsed: List[Tuple[str, set]] = [(tag, _file_names_in(prov)) for tag, prov in rows if prov]
    for name in file_names:
        base = _COMPANION.sub("", str(name).replace("\\", "/").rsplit("/", 1)[-1].strip().lower())
        if not base:
            continue
        hit: Dict[str, int] = {}
        for tag, names in parsed:
            if base in names:
                hit[tag] = hit.get(tag, 0) + 1
        if hit:
            out[name] = hit
    return out
