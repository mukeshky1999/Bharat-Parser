"""Stage A: Android backups (.ab) and iOS backup folders are read through src/vfs, and the evidence is not touched."""
import hashlib
import io
import os
import plistlib
import sqlite3
import tarfile
import zlib

import pytest
from fastapi.testclient import TestClient

from parsers import api_server


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _payments_db_bytes(tmp_path, name="p.db"):
    p = tmp_path / name
    c = sqlite3.connect(p)
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.executemany('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', [
        ("A", 1111.11, "me@ybl", "one@ybl", "100000000001", "2026-02-01 09:00:00"),
        ("B", 2222.22, "me@ybl", "two@ybl", "100000000002", "2026-02-02 09:00:00")])
    c.commit()
    c.close()
    data = p.read_bytes()
    p.unlink()
    return data


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _rows(res):
    c = sqlite3.connect(res["workspace_dir"] + "/bharat_case_store.db")
    c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT * FROM transactions")]
    c.close()
    return rows


@pytest.mark.parametrize("compressed", [False, True])
def test_android_backup_is_read_and_unchanged(client, tmp_path, compressed):
    tar = _tar({"apps/com.pay.app/db/payments.db": _payments_db_bytes(tmp_path), "apps/com.pay.app/_manifest": b"m"})
    body = zlib.compress(tar) if compressed else tar
    ab = tmp_path / "phone.ab"
    ab.write_bytes(b"ANDROID BACKUP\n5\n" + (b"1" if compressed else b"0") + b"\nnone\n" + body)
    before = _sha(ab)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ab), "case_id": "AB-1"}).json()
    assert res["success"], res
    rows = _rows(res)
    assert sorted(r["Transaction_ID"] for r in rows) == ["100000000001", "100000000002"]
    assert "payments.db" in rows[0]["Source_File"]
    assert _sha(ab) == before and res["hashes"]["integrityMatch"] is True
    assert any(e["stage"] == "parse_database" and e["file"] == "payments.db" and e["status"] == "OK"
               for e in res["processing_log"])


def _ios_backup(tmp_path, with_file=True, encrypted=False, size_in_manifest=False):
    root = tmp_path / "ios_backup"
    root.mkdir()
    file_id = "ab" + "c" * 38
    man = root / "Manifest.db"
    c = sqlite3.connect(man)
    c.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    blob = plistlib.dumps({"$objects": ["$null", {"Size": 4096}]}) if size_in_manifest else None
    c.execute("INSERT INTO Files VALUES (?, 'AppDomain-com.pay.app', 'Library/databases/payments.db', 1, ?)", (file_id, blob))
    c.commit()
    c.close()
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": encrypted}))
    (root / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "Test"}))
    if with_file:
        (root / file_id[:2]).mkdir()
        (root / file_id[:2] / file_id).write_bytes(_payments_db_bytes(tmp_path, "src.db"))
    return root


def _tree_hash(root):
    h = hashlib.sha256()
    for r, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            h.update(os.path.relpath(os.path.join(r, f), root).encode())
            h.update(open(os.path.join(r, f), "rb").read())
    return h.hexdigest()


def test_ios_backup_files_get_their_real_paths_and_are_parsed(client, tmp_path):
    root = _ios_backup(tmp_path)
    before = _tree_hash(root)
    res = client.post("/api/case/ingest", json={"evidence_path": str(root), "case_id": "IOS-1"}).json()
    assert res["success"], res
    rows = _rows(res)
    assert len(rows) == 2
    assert "private/var/mobile/Containers/Data/Application/com.pay.app/Library/databases/payments.db" in rows[0]["Source_File"]
    assert _tree_hash(root) == before, "indexing must not change Manifest.db or anything else in the backup"
    assert res["hashes"]["integrityMatch"] is True


def test_ios_backup_with_a_missing_file_says_which(client, tmp_path):
    root = _ios_backup(tmp_path, with_file=False, size_in_manifest=True)
    res = client.post("/api/case/ingest", json={"evidence_path": str(root), "case_id": "IOS-2"}).json()
    failed = [e for e in res["processing_log"] if e["stage"] == "extract" and e["status"] == "FAILED"]
    assert failed and failed[0]["file"] == "payments.db"


def test_encrypted_ios_backup_is_refused_with_the_reason(client, tmp_path):
    root = _ios_backup(tmp_path, encrypted=True)
    r = client.post("/api/case/ingest", json={"evidence_path": str(root), "case_id": "IOS-3"})
    assert r.status_code == 422 and "encrypted" in r.json()["detail"] and "Nothing was ingested" in r.json()["detail"]


def test_encrypted_android_backup_is_refused_with_the_reason(client, tmp_path):
    ab = tmp_path / "enc.ab"
    ab.write_bytes(b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"\x00" * 200)
    r = client.post("/api/case/ingest", json={"evidence_path": str(ab), "case_id": "AB-2"})
    assert r.status_code == 422 and "Nothing was ingested" in r.json()["detail"]


def test_a_member_path_that_leaves_the_folder_is_reported_not_silently_dropped(client, tmp_path):
    tar = _tar({"apps/x/db/ok.db": _payments_db_bytes(tmp_path), "../../evil/payments.db": b"x" * 64})
    ab = tmp_path / "t.ab"
    ab.write_bytes(b"ANDROID BACKUP\n5\n0\nnone\n" + tar)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ab), "case_id": "AB-3"}).json()
    assert res["success"]
    assert not os.path.exists(tmp_path / "evil")
    assert not os.path.exists(os.path.join(res["workspace_dir"], "evil"))
