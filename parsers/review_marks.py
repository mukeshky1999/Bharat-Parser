"""
Phase 5C.10: the reviewer round trip.

The reviewer opens the portable package on any computer, marks the files, and saves a small file of marks. The
examiner imports that file. What this module guarantees:

* A marks file is accepted only if it names a package this case built (``package_id`` is the SHA-256 of that
  package's ``manifest.json``, written to the audit log when the package was built) and every mark carries the
  SHA-256 of a file that package holds. A file from some other package, or a mark on a file the package does not
  hold, is refused whole.
* The same marks file is not imported twice.
* Marks are the REVIEWER'S suggestions. They are stored apart from tags and never turn into tags by themselves:
  tags are the examiner's decisions.
* The reviewer's name and the reviewer's clock are kept as the reviewer typed them / as their computer said, and are
  labelled so. Neither is checked.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviewer_marks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Package_Id TEXT NOT NULL,
    Reviewer TEXT,
    Reviewer_Clock TEXT,
    File_Index TEXT NOT NULL,
    File_Name TEXT,
    File_Sha256 TEXT NOT NULL,
    Label TEXT,
    Note TEXT,
    Marks_File_Sha256 TEXT NOT NULL,
    Imported_At_Utc TEXT NOT NULL,
    UNIQUE (Marks_File_Sha256, File_Index)
);
CREATE INDEX IF NOT EXISTS idx_reviewer_marks_pkg ON reviewer_marks(Package_Id);
"""

LABELS = ("relevant", "not_relevant", "needs_clarification")
MAX_TEXT_BYTES = 2_000_000
MAX_MARKS = 5000
MAX_NOTE = 2000
MAX_NAME = 120


class MarksRefused(ValueError):
    """The marks file was not imported; the message says why."""


def import_marks(conn: sqlite3.Connection, text: str, known_packages: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    raw = text.encode("utf-8") if isinstance(text, str) else b""
    if not raw or len(raw) > MAX_TEXT_BYTES:
        raise MarksRefused("The marks file is empty or larger than 2 MB.")
    try:
        doc = json.loads(text)
    except ValueError:
        raise MarksRefused("The file is not a marks file (it is not valid JSON).")
    if not isinstance(doc, dict) or doc.get("kind") != "reviewer_marks" or doc.get("schema") != 1:
        raise MarksRefused("The file is not a reviewer marks file of this version.")
    pid = str(doc.get("package_id") or "")
    pkg = known_packages.get(pid)
    if pkg is None:
        raise MarksRefused("These marks are for a package this case did not build (its package id is not in the audit log). Nothing was imported.")
    marks = doc.get("marks")
    if not isinstance(marks, list) or not marks:
        raise MarksRefused("The file holds no marks.")
    if len(marks) > MAX_MARKS:
        raise MarksRefused(f"More than {MAX_MARKS} marks.")
    items = {str(i["index"]): i for i in pkg["items"]}
    clean: List[Dict[str, str]] = []
    for m in marks:
        if not isinstance(m, dict):
            raise MarksRefused("A mark is not an object.")
        idx, sha = str(m.get("index") or ""), str(m.get("sha256") or "").lower()
        if idx not in items or items[idx]["sha256"] != sha:
            raise MarksRefused(f"Mark for file {idx or '?'} does not match a file of that package (the SHA-256 differs). Nothing was imported.")
        label = m.get("label")
        if label not in LABELS and label not in (None, ""):
            raise MarksRefused(f"Unknown mark '{str(label)[:40]}' on file {idx}.")
        note = str(m.get("note") or "")
        if len(note) > MAX_NOTE:
            raise MarksRefused(f"The note on file {idx} is longer than {MAX_NOTE} characters.")
        if not label and not note.strip():
            continue                                   # an empty row says nothing
        clean.append({"index": idx, "name": items[idx].get("name", ""), "sha256": sha, "label": label or "", "note": note})
    if not clean:
        raise MarksRefused("Every mark is empty.")
    marks_sha = hashlib.sha256(raw).hexdigest()
    if conn.execute("SELECT 1 FROM reviewer_marks WHERE Marks_File_Sha256 = ? LIMIT 1", (marks_sha,)).fetchone():
        raise MarksRefused("This marks file was already imported.")
    reviewer = " ".join(str(doc.get("reviewer") or "").split())[:MAX_NAME]
    clock = str(doc.get("reviewer_clock") or "")[:40]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for c in clean:
        conn.execute(
            "INSERT INTO reviewer_marks (Package_Id, Reviewer, Reviewer_Clock, File_Index, File_Name, File_Sha256, Label, Note, Marks_File_Sha256, Imported_At_Utc) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (pid, reviewer or None, clock or None, c["index"], c["name"], c["sha256"], c["label"] or None, c["note"] or None, marks_sha, now))
    conn.commit()
    return {"imported": len(clean), "package_id": pid, "reviewer": reviewer or None, "marks_file_sha256": marks_sha}


def list_marks(conn: sqlite3.Connection) -> Dict[str, Any]:
    rows = [dict(r) for r in conn.execute("SELECT * FROM reviewer_marks ORDER BY id")]
    return {
        "marks": rows,
        "note": ("These are the reviewer's suggestions, as the reviewer typed them. The reviewer's name and clock are not checked. "
                 "A mark is not a tag: tag records yourself to make a decision."),
    }
