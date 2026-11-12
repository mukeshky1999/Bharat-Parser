"""The case file: what a case is, kept on disk beside its record store (Phase 5B.2).

A case holds one or more evidence items (one per phone, image or folder). Everything the examiner needs to
reopen the case later without processing the evidence again is kept here: the items, their hashes before and
after processing, the device facts, the processing log, the owner profile and the link analysis of each item.

One SQLite file per case workspace: ``case_file.sqlite``. Nothing here is inferred; a value that was not
recorded is stored as NULL and reported as "Not recorded" by the callers.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

FILE_NAME = "case_file.sqlite"
SCHEMA_VERSION = 1

_JSON_FIELDS = ("hashes", "device", "processing_log", "dossier", "analysis", "record_counts")
_FIELDS = ("label", "source_path", "kind", "added_utc", "integrity_match", "status") + _JSON_FIELDS


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _now_precise() -> str:
    """Microsecond resolution, so two cases opened in the same second still sort in the order they were opened."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def safe_case_dir_name(case_id: str) -> str:
    """A case id becomes a folder name. Nothing that could leave the cases folder survives."""
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", str(case_id)).strip("._")
    return clean[:80] or "case"


class CaseFile:
    def __init__(self, workspace: str) -> None:
        self.workspace = workspace
        os.makedirs(workspace, exist_ok=True)
        self.path = os.path.join(workspace, FILE_NAME)
        self._init()

    # ------------------------------------------------------------------ plumbing
    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        c = self._conn()
        try:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS case_info (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS evidence_items (
                    item_id TEXT PRIMARY KEY,
                    seq INTEGER NOT NULL,
                    label TEXT,
                    source_path TEXT,
                    kind TEXT,
                    added_utc TEXT,
                    integrity_match INTEGER,
                    status TEXT,
                    hashes TEXT, device TEXT, processing_log TEXT, dossier TEXT, analysis TEXT, record_counts TEXT
                );
            """)
            c.execute("INSERT OR IGNORE INTO case_info(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.commit()
        finally:
            c.close()

    # ------------------------------------------------------------------ case level
    def info(self) -> Dict[str, str]:
        c = self._conn()
        try:
            return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM case_info")}
        finally:
            c.close()

    def set_info(self, **kv: Optional[str]) -> None:
        c = self._conn()
        try:
            for k, v in kv.items():
                c.execute("INSERT INTO case_info(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (k, "" if v is None else str(v)))
            c.commit()
        finally:
            c.close()

    def touch_opened(self) -> None:
        self.set_info(last_opened_utc=_now_precise())

    # ------------------------------------------------------------------ evidence items
    def _row_to_item(self, r: sqlite3.Row) -> Dict[str, Any]:
        item: Dict[str, Any] = {"item_id": r["item_id"], "seq": r["seq"]}
        for f in _FIELDS:
            v = r[f]
            if f in _JSON_FIELDS:
                try:
                    item[f] = json.loads(v) if v else None
                except ValueError:
                    item[f] = None
            elif f == "integrity_match":
                item[f] = None if v is None else bool(v)
            else:
                item[f] = v
        return item

    def items(self) -> List[Dict[str, Any]]:
        c = self._conn()
        try:
            return [self._row_to_item(r) for r in c.execute("SELECT * FROM evidence_items ORDER BY seq")]
        finally:
            c.close()

    def get_item(self, item_id: str) -> Optional[Dict[str, Any]]:
        c = self._conn()
        try:
            r = c.execute("SELECT * FROM evidence_items WHERE item_id=?", (item_id,)).fetchone()
            return self._row_to_item(r) if r else None
        finally:
            c.close()

    def item_for_source(self, source_path: str) -> Optional[Dict[str, Any]]:
        want = os.path.normcase(os.path.abspath(source_path))
        for it in self.items():
            if it.get("source_path") and os.path.normcase(os.path.abspath(it["source_path"])) == want:
                return it
        return None

    def next_item_id(self) -> str:
        c = self._conn()
        try:
            n = (c.execute("SELECT COALESCE(MAX(seq), 0) FROM evidence_items").fetchone()[0] or 0) + 1
        finally:
            c.close()
        return f"EV-{n:03d}"

    def upsert_item(self, item_id: str, **fields: Any) -> Dict[str, Any]:
        unknown = set(fields) - set(_FIELDS)
        if unknown:
            raise ValueError(f"unknown evidence item fields: {sorted(unknown)}")
        c = self._conn()
        try:
            row = c.execute("SELECT seq FROM evidence_items WHERE item_id=?", (item_id,)).fetchone()
            if row is None:
                seq = (c.execute("SELECT COALESCE(MAX(seq), 0) FROM evidence_items").fetchone()[0] or 0) + 1
                c.execute("INSERT INTO evidence_items(item_id, seq, added_utc) VALUES (?, ?, ?)", (item_id, seq, _now()))
            for k, v in fields.items():
                if k in _JSON_FIELDS:
                    v = None if v is None else json.dumps(v, ensure_ascii=False, default=str)
                elif k == "integrity_match":
                    v = None if v is None else int(bool(v))
                c.execute(f"UPDATE evidence_items SET {k}=? WHERE item_id=?", (v, item_id))
            c.commit()
        finally:
            c.close()
        return self.get_item(item_id) or {}

    def remove_all_items(self) -> None:
        c = self._conn()
        try:
            c.execute("DELETE FROM evidence_items")
            c.commit()
        finally:
            c.close()


def list_cases(root: str) -> List[Dict[str, Any]]:
    """The cases found under ``root``, most recently opened first. A folder without a case file is not a case."""
    out: List[Dict[str, Any]] = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        ws = os.path.join(root, name)
        if not os.path.isfile(os.path.join(ws, FILE_NAME)):
            continue
        try:
            cf = CaseFile(ws)
            info = cf.info()
            items = cf.items()
        except sqlite3.Error:
            continue
        out.append({
            "case_id": info.get("case_id") or name,
            "case_name": info.get("case_name") or "",
            "examiner_name": info.get("examiner_name") or "",
            "workspace": ws,
            "created_utc": info.get("created_utc") or "",
            "last_opened_utc": info.get("last_opened_utc") or info.get("created_utc") or "",
            "evidence_items": [
                {"item_id": i["item_id"], "label": i.get("label") or "", "source_path": i.get("source_path") or "",
                 "integrity_match": i.get("integrity_match")}
                for i in items
            ],
        })
    out.sort(key=lambda c: c["last_opened_utc"], reverse=True)
    return out
