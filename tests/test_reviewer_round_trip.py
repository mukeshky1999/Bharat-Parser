"""5C.10: marks made by a reviewer on a package come back as a file bound to that package."""
import hashlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server, review_marks
from parsers.review_package import INCLUDE, PackageItem, build_package


def _pkg(tmp_path):
    f = tmp_path / "a.txt"; f.write_bytes(b"alpha")
    g = tmp_path / "b.txt"; g.write_bytes(b"beta")
    res = build_package("C1", [PackageItem(str(f), INCLUDE), PackageItem(str(g), "WITHHOLD_PRIVILEGED")], str(tmp_path / "pkg"))
    return res, {res.package_id: {"items": res.entries}}


def _marks(res, **over):
    e = res.entries
    doc = {"kind": "reviewer_marks", "schema": 1, "package_id": res.package_id, "reviewer": "R. Reviewer", "reviewer_clock": "2026-11-12T10:00:00Z",
           "marks": [{"index": e[0]["index"], "sha256": e[0]["sha256"], "label": "relevant", "note": "looks right"},
                     {"index": e[1]["index"], "sha256": e[1]["sha256"], "label": "", "note": ""}]}
    doc.update(over)
    return json.dumps(doc)


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(str(tmp_path / "m.db")); c.row_factory = sqlite3.Row
    c.executescript(review_marks.SCHEMA)
    yield c
    c.close()


def test_package_id_is_the_hash_of_the_manifest(tmp_path):
    res, _ = _pkg(tmp_path)
    assert res.package_id == hashlib.sha256(open(res.manifest_path, "rb").read()).hexdigest()
    assert res.package_id in open(res.viewer_path, encoding="utf-8").read()


def test_marks_for_a_known_package_import_and_empty_rows_are_dropped(conn, tmp_path):
    res, known = _pkg(tmp_path)
    r = review_marks.import_marks(conn, _marks(res), known)
    assert r["imported"] == 1 and r["reviewer"] == "R. Reviewer"
    row = review_marks.list_marks(conn)["marks"][0]
    assert row["Label"] == "relevant" and row["Note"] == "looks right" and row["File_Name"] == "a.txt"
    assert "not a tag" in review_marks.list_marks(conn)["note"]


def test_same_file_twice_unknown_package_wrong_hash_and_bad_label_are_refused(conn, tmp_path):
    res, known = _pkg(tmp_path)
    text = _marks(res)
    review_marks.import_marks(conn, text, known)
    with pytest.raises(review_marks.MarksRefused, match="already imported"):
        review_marks.import_marks(conn, text, known)
    with pytest.raises(review_marks.MarksRefused, match="did not build"):
        review_marks.import_marks(conn, _marks(res, package_id="0" * 64), known)
    bad = json.loads(text); bad["marks"][0]["sha256"] = "f" * 64; bad["reviewer"] = "x"
    with pytest.raises(review_marks.MarksRefused, match="SHA-256 differs"):
        review_marks.import_marks(conn, json.dumps(bad), known)
    lab = json.loads(text); lab["marks"][0]["label"] = "guilty"; lab["reviewer"] = "y"
    with pytest.raises(review_marks.MarksRefused, match="Unknown mark"):
        review_marks.import_marks(conn, json.dumps(lab), known)
    for junk in ("", "not json", "[]", json.dumps({"kind": "other"})):
        with pytest.raises(review_marks.MarksRefused):
            review_marks.import_marks(conn, junk, known)
    assert len(review_marks.list_marks(conn)["marks"]) == 1          # a refused file imports nothing


def test_marks_never_become_tags(conn, tmp_path):
    res, known = _pkg(tmp_path)
    review_marks.import_marks(conn, _marks(res), known)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "tags" not in names or conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0] == 0


def test_endpoints_audit_and_package_must_come_from_this_case(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    ev = tmp_path / "ev"; ev.mkdir()
    c = sqlite3.connect(ev / "p.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("t", 10.0, "a@ybl", "b@ybl", "100000000011", "2026-02-01 09:00:00")); c.commit(); c.close()
    client = TestClient(api_server.app)
    assert client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "RT-1"}).json()["success"]
    ws = api_server._active_store.case_workspace
    items = [{"path": str(ev / "p.db"), "disposition": "INCLUDE"}]
    pk = client.post("/api/report/package", json={"items": items})
    assert pk.status_code == 200, pk.text
    pid = pk.json()["package_id"]
    audit = client.get("/api/audit").json()
    built = [e for e in audit["entries"] if e["action"] == "package_built"][-1]
    assert built["payload"]["package_id"] == pid and built["payload"]["items"][0]["sha256"]
    entry = built["payload"]["items"][0]
    doc = {"kind": "reviewer_marks", "schema": 1, "package_id": pid, "reviewer": "Rev", "reviewer_clock": "2026-11-12T00:00:00Z",
           "marks": [{"index": entry["index"], "sha256": entry["sha256"], "label": "needs_clarification", "note": "what is this"}]}
    ok = client.post("/api/review/marks/import", json={"text": json.dumps(doc)})
    assert ok.status_code == 200 and ok.json()["imported"] == 1
    assert client.post("/api/review/marks/import", json={"text": json.dumps(doc)}).status_code == 422          # not twice
    doc["package_id"] = "1" * 64
    assert client.post("/api/review/marks/import", json={"text": json.dumps(doc)}).status_code == 422          # not this case's package
    marks = client.get("/api/review/marks").json()["marks"]
    assert len(marks) == 1 and marks[0]["Label"] == "needs_clarification"
    actions = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert "reviewer_marks_imported" in actions
    assert client.get("/api/case/tags").json()["tags"] and all(t["count"] == 0 for t in client.get("/api/case/tags").json()["tags"])
