"""
Phase 5B.5: search across every table of the case store.

Modes
-----
keyword   every word must occur (any field the full-text index covers); a word also matches longer words that start with it.
phrase    the words must occur next to each other, in order (same index).
contains  the text occurs anywhere inside a field, including inside a number or an identifier. Text is compared after
          Unicode normalisation (NFKC), with zero-width joiners removed, case folded, and digits of any script
          (Devanagari, Bengali, Tamil, ...) read as 0-9. Reads every row, so it is slower.
regex     a regular expression (case-insensitive), compared field by field. Reads every row.

What the result says about itself
---------------------------------
* ``searched_fields`` per table: the fields the search looked in. The full-text index does not cover numeric fields
  such as Amount; ``contains`` and ``regex`` do.
* ``complete``: False when a time limit stopped a row scan, so a count is then "at least". Nothing is guessed.
* ``cells_cut``: fields longer than the scan limit are compared only up to it, and this counts them.

A search never changes the case store.
"""
from __future__ import annotations

import re
import sqlite3
import time
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MODES = ("keyword", "phrase", "contains", "regex")
MAX_QUERY_CHARS = 300
MAX_REGEX_CHARS = 200
SCAN_CELL_LIMIT = 20000
SNIPPET_RADIUS = 40
DEFAULT_TIME_BUDGET_S = 20.0

_NEVER_SEARCHED = {"id", "Evidence_Item", "Decoded_By"}
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
# A group that is itself repeated, such as (a+)+ or (.*)*, can take exponential time in Python's matcher.
_NESTED_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


class SearchError(ValueError):
    """The query cannot be run; the message says why."""


def fold(text: Any) -> str:
    """Comparison form of a value: NFKC, no zero-width characters, digits of any script as 0-9, case folded."""
    s = unicodedata.normalize("NFKC", str(text)).translate(_ZERO_WIDTH)
    if s.isascii():
        return s.casefold()
    return "".join(str(unicodedata.digit(ch)) if unicodedata.category(ch) == "Nd" else ch for ch in s).casefold()


def _terms(query: str) -> List[str]:
    return [t for t in fold(query).split() if t]


def _fts_expression(query: str, mode: str) -> str:
    q = unicodedata.normalize("NFC", query).translate(_ZERO_WIDTH).strip()
    if mode == "phrase":
        return '"' + q.replace('"', '""') + '"'
    words = [w for w in q.split() if w]
    return " ".join('"' + w.replace('"', '""') + '" *' for w in words)


def check_regex(pattern: str) -> "re.Pattern[str]":
    if len(pattern) > MAX_REGEX_CHARS:
        raise SearchError(f"The pattern is longer than {MAX_REGEX_CHARS} characters.")
    if _NESTED_REPEAT.search(pattern):
        raise SearchError("A repeated group inside a repeat (for example (a+)+) can run for a very long time and is not allowed.")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise SearchError(f"The pattern is not valid: {exc}")


def _tables(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def _columns(conn: sqlite3.Connection, table: str) -> List[Tuple[str, str]]:
    return [(r[1], (r[2] or "").upper()) for r in conn.execute(f'PRAGMA table_info("{table}")')]


def _fts_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    if f"{table}_fts" not in _tables(conn):
        return []
    return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}_fts")')]


def _first(row: Dict[str, Any], names: Sequence[str]) -> str:
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            return str(v)
    return ""


def _snippet(value: str, needles: Sequence[str], pattern: Optional["re.Pattern[str]"]) -> str:
    text = str(value)
    pos, length = -1, 0
    if pattern is not None:
        m = pattern.search(text[:SCAN_CELL_LIMIT])
        if m:
            pos, length = m.start(), max(1, m.end() - m.start())
    else:
        # The folded text can differ in length from the original, so look for the needle in the original first.
        low = text.casefold()
        for nd in needles:
            i = low.find(nd)
            if i >= 0:
                pos, length = i, len(nd)
                break
    if pos < 0:
        return text[: 2 * SNIPPET_RADIUS] + ("…" if len(text) > 2 * SNIPPET_RADIUS else "")
    a, b = max(0, pos - SNIPPET_RADIUS), min(len(text), pos + length + SNIPPET_RADIUS)
    return ("…" if a else "") + text[a:b] + ("…" if b < len(text) else "")


def _hit(table: str, row: Dict[str, Any], fields: Sequence[str], needles: Sequence[str],
         pattern: Optional["re.Pattern[str]"], rank: Optional[float]) -> Dict[str, Any]:
    matched: List[str] = []
    snippet = ""
    for f in fields:
        v = row.get(f)
        if v in (None, ""):
            continue
        folded = fold(str(v)[:SCAN_CELL_LIMIT])
        ok = bool(pattern.search(str(v)[:SCAN_CELL_LIMIT])) if pattern is not None else any(n in folded for n in needles)
        if ok:
            matched.append(f)
            if not snippet:
                snippet = _snippet(str(v), needles, pattern)
    return {
        "table": table,
        "id": row.get("id"),
        "evidence_item": row.get("Evidence_Item"),
        "application": _first(row, ("Application", "Source_App")),
        "source_file": _first(row, ("Source_File", "vfs_path", "file_name")),
        "time": _first(row, ("Timestamp_IST", "Timestamp_UTC", "Date", "Start_Time", "Timestamp")),
        "decoded_by": row.get("Decoded_By"),
        "matched_fields": matched,
        "snippet": snippet,
        "provenance": row.get("Forensic_Provenance"),
        "rank": rank,
    }


def search_case(
    conn: sqlite3.Connection,
    query: str,
    mode: str = "keyword",
    tables: Optional[Iterable[str]] = None,
    evidence_item: Optional[str] = None,
    application: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    time_budget_s: float = DEFAULT_TIME_BUDGET_S,
    allowed_tables: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    query = (query or "").strip()
    if not query:
        raise SearchError("The search text is empty.")
    if len(query) > MAX_QUERY_CHARS:
        raise SearchError(f"The search text is longer than {MAX_QUERY_CHARS} characters.")
    if mode not in MODES:
        raise SearchError(f"Unknown mode {mode!r}. Use one of: {', '.join(MODES)}.")
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    pattern = check_regex(query) if mode == "regex" else None
    needles = [] if pattern is not None else ([fold(query)] if mode in ("phrase", "contains") else _terms(query))
    if mode in ("keyword", "phrase") and not _terms(query):
        raise SearchError("The search text has no words in it.")

    present = set(_tables(conn))
    wanted = [t for t in (allowed_tables or []) if t in present]
    if tables:
        asked = [t.lower().strip() for t in tables]
        unknown = [t for t in asked if t not in wanted]
        if unknown:
            raise SearchError(f"Not a searchable table here: {', '.join(unknown)}.")
        wanted = [t for t in wanted if t in asked]

    hits: List[Dict[str, Any]] = []
    per_table: Dict[str, Dict[str, Any]] = {}
    complete = True
    cells_cut = 0
    need = offset + limit

    for t in sorted(wanted):
        cols = _columns(conn, t)
        names = [c for c, _ in cols]
        scan_fields = [c for c in names if c not in _NEVER_SEARCHED]
        where, params = [], []
        if evidence_item and "Evidence_Item" in names:
            where.append("t.Evidence_Item = ?")
            params.append(evidence_item)
        if application and "Application" in names:
            where.append("t.Application = ?")
            params.append(application)
        extra = (" AND " + " AND ".join(where)) if where else ""

        fts_cols = _fts_columns(conn, t)
        info: Dict[str, Any] = {"count": 0, "count_is_exact": True, "searched_fields": []}
        t_hits: List[Dict[str, Any]] = []

        if mode in ("keyword", "phrase"):
            if not fts_cols:
                info.update(skipped="no full-text index for this table; use mode 'contains'")
                per_table[t] = info
                continue
            expr = _fts_expression(query, mode)
            base = f'FROM "{t}" t JOIN "{t}_fts" ON t.id = "{t}_fts".rowid WHERE "{t}_fts" MATCH ?{extra}'
            try:
                info["count"] = conn.execute(f"SELECT COUNT(*) {base}", [expr] + params).fetchone()[0]
                cur = conn.execute(f'SELECT t.*, bm25("{t}_fts") AS _rank {base} ORDER BY _rank LIMIT ? OFFSET ?',
                                   [expr] + params + [max(0, need - len(hits)), 0])
            except sqlite3.OperationalError as exc:
                raise SearchError(f"The search text cannot be used as a keyword search: {exc}")
            cn = [d[0] for d in cur.description]
            for r in cur:
                row = dict(zip(cn, r))
                t_hits.append(_hit(t, row, fts_cols, needles, None, row.get("_rank")))
            info["searched_fields"] = fts_cols
        else:
            cur = conn.execute(f'SELECT t.* FROM "{t}" t WHERE 1=1{extra}', params)
            cn = [d[0] for d in cur.description]
            n = 0
            for r in cur:
                row = dict(zip(cn, r))
                found = False
                for f in scan_fields:
                    v = row.get(f)
                    if v is None or v == "":
                        continue
                    s = v if isinstance(v, str) else str(v)
                    if len(s) > SCAN_CELL_LIMIT:
                        s = s[:SCAN_CELL_LIMIT]
                        cells_cut += 1
                    if (pattern.search(s) if pattern is not None else needles[0] in fold(s)):
                        found = True
                        break
                if found:
                    n += 1
                    if len(hits) + len(t_hits) < need:
                        t_hits.append(_hit(t, row, scan_fields, needles, pattern, None))
                if time.monotonic() - started > time_budget_s:
                    complete = False
                    info["count_is_exact"] = False
                    break
            info["count"] = n
            info["searched_fields"] = scan_fields
        hits.extend(t_hits)
        per_table[t] = info
        if not complete:
            break

    total = sum(i["count"] for i in per_table.values())
    page = hits[offset: offset + limit]
    return {
        "query": query,
        "mode": mode,
        "total": total,
        "total_is_exact": complete and all(i["count_is_exact"] for i in per_table.values()),
        "offset": offset,
        "limit": limit,
        "hits": page,
        "tables": per_table,
        "complete": complete,
        "stopped_reason": None if complete else f"The time limit of {time_budget_s:g} s was reached; later tables and rows were not searched.",
        "cells_cut": cells_cut,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
