"""5B.3: the ingest reports what it is really doing, readable through an endpoint while it runs."""
import os
import plistlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _evidence(tmp_path, names=("a_payments.db", "b_payments.db")):
    ev = tmp_path / "ev"
    ev.mkdir()
    for n in names:
        c = sqlite3.connect(ev / n)
        c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
        c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', (n, 1500.0, "me@ybl", "x@ybl", "10000000000" + n[0].upper().replace("A", "1").replace("B", "2"), "2026-02-01 09:00:00"))
        c.commit()
        c.close()
    return ev


def test_progress_is_idle_before_any_ingest():
    p = api_server.IngestProgress()
    p.state = "idle"
    s = p.snapshot()
    assert s["state"] == "idle" and s["stage"] == "" and s["stage_index"] == 0 and s["fraction"] is None


def test_stages_run_in_order_and_files_are_counted_while_reading(client, tmp_path, monkeypatch):
    seen = []
    real = api_server.parse_database_artifacts

    def spy(*a, **kw):
        # called from inside the running pipeline: ask the real endpoint what it says right now
        seen.append(client.get("/api/case/ingest/progress").json())
        return real(*a, **kw)

    monkeypatch.setattr(api_server, "parse_database_artifacts", spy)
    res = client.post("/api/case/ingest", json={"evidence_path": str(_evidence(tmp_path)), "case_id": "PR-1"}).json()
    assert res["success"]

    assert len(seen) == 2
    for i, s in enumerate(seen):
        assert s["state"] == "running" and s["stage"] == "parse" and s["stage_label"] == "Reading databases"
        assert s["stage_index"] == 4 and s["stage_count"] == 11
        assert s["unit"] == "files" and s["units_total"] == 2
        assert s["units_done"] == i and s["fraction"] == i / 2
        assert s["detail"].endswith("_payments.db")
    assert seen[0]["detail"] != seen[1]["detail"]

    final = client.get("/api/case/ingest/progress").json()
    assert final["state"] == "succeeded" and final["evidence_item"] == "EV-001"
    stages = [e["stage"] for e in final["events"] if e["kind"] == "stage"]
    assert stages == [k for k, _ in api_server.IngestProgress.STAGES], stages
    assert final["events"][-1]["kind"] == "done"
    assert final["processing_log_count"] == len(res["processing_log"])
    # an event after the last one seen is the only thing a later poll gets
    later = client.get("/api/case/ingest/progress", params={"since": final["seq"] - 1}).json()
    assert [e["kind"] for e in later["events"]] == ["done"]
    assert client.get("/api/case/ingest/progress", params={"since": final["seq"]}).json()["events"] == []


def test_hashing_reports_the_bytes_it_has_read(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(20 * 1024 * 1024 + 123))
    got = []
    h = api_server.compute_hashes_streaming(str(f), on_bytes=got.append)
    assert sum(got) == h["fileSizeBytes"] == os.path.getsize(f)
    assert len(got) >= 3                                           # several 8 MB chunks, so progress moves during the read
    d = tmp_path / "dir"
    d.mkdir()
    (d / "a").write_bytes(b"x" * 1000)
    (d / "b").write_bytes(b"y" * 500)
    got2 = []
    api_server.compute_hashes_streaming(str(d), on_bytes=got2.append)
    assert sum(got2) == api_server._evidence_size(str(d)) == 1500


def test_fraction_is_none_when_the_total_is_unknown_and_never_invented():
    p = api_server.IngestProgress()
    p.stage("extract", unit="entries")
    p.progress(10)
    s = p.snapshot()
    assert s["units_done"] == 10 and s["units_total"] is None and s["fraction"] is None and s["stage_eta_s"] is None


def test_estimate_appears_only_once_five_percent_is_done():
    p = api_server.IngestProgress()
    p.stage("hash_evidence", total=1000, unit="bytes")
    p.add(10)
    assert p.snapshot()["stage_eta_s"] is None
    p.add(90)
    s = p.snapshot()
    assert s["fraction"] == 0.1 and s["stage_eta_s"] is not None and s["stage_eta_s"] >= 0


def test_a_refused_container_shows_as_failed_with_the_reason(client, tmp_path):
    root = tmp_path / "bk"
    root.mkdir()
    c = sqlite3.connect(root / "Manifest.db")
    c.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    c.commit()
    c.close()
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
    r = client.post("/api/case/ingest", json={"evidence_path": str(root), "case_id": "PR-2"})
    assert r.status_code == 422
    s = client.get("/api/case/ingest/progress").json()
    assert s["state"] == "failed" and "encrypted" in s["message"] and s["stage"] == "extract"
    assert s["events"][-1]["kind"] == "failed"


def test_a_new_ingest_replaces_the_previous_job(client, tmp_path):
    ev = _evidence(tmp_path, names=("a_payments.db",))
    client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "PR-3"})
    first = client.get("/api/case/ingest/progress").json()["job_id"]
    client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "PR-3"})
    assert client.get("/api/case/ingest/progress").json()["job_id"] != first
