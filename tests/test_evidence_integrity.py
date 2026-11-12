"""Evidence-integrity regression tests (REVIEW_FINDINGS C-01, C-02, C-05, H-01)."""
import hashlib
import os
import sqlite3
import zipfile

import pytest

from parsers import api_server
from parsers.api_server import compute_hashes_streaming
from parsers.enterprise_1tb_chat_and_container_engine import TerabyteForensicContainerEngine


def _snapshot(folder):
    snap = {}
    for root, _, files in os.walk(folder):
        for f in files:
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                snap[os.path.relpath(p, folder)] = hashlib.sha256(fh.read()).hexdigest()
    return snap


@pytest.fixture(autouse=True)
def _restore_api_globals(monkeypatch):
    """The pipeline rebinds module globals; restore them so other tests keep their references."""
    monkeypatch.setattr(api_server, "_case_state", api_server._case_state)
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)


@pytest.fixture
def wal_folder(tmp_path):
    folder = tmp_path / "evidence"
    folder.mkdir()
    db = folder / "msgstore.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT)")
    conn.commit()
    for i in range(20):
        conn.execute("INSERT INTO message (text_data) VALUES (?)", (f"hello {i}",))
    conn.commit()
    # Copy while the connection is open so the -wal file is un-checkpointed.
    staged = tmp_path / "staged"
    staged.mkdir()
    for name in os.listdir(folder):
        if name.endswith(("-shm",)):
            continue
        with open(folder / name, "rb") as s, open(staged / name, "wb") as d:
            d.write(s.read())
    conn.close()
    return staged


def test_wal_folder_present(wal_folder):
    assert (wal_folder / "msgstore.db-wal").exists()


def test_api_ingest_does_not_modify_evidence_and_reports_post_hash(wal_folder, tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    before = _snapshot(wal_folder)
    result = api_server._execute_ingestion_pipeline(
        str(wal_folder), "CASE-INTEG", "Integrity", "Examiner", "Agency"
    )
    assert _snapshot(wal_folder) == before
    assert result["integrity_match"] is True
    assert result["hashes"]["postIngestionSha256"] == result["hashes"]["sha256"]


def test_folder_hash_depends_on_file_names(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "one.bin").write_bytes(b"x")
    (b / "two.bin").write_bytes(b"x")
    assert compute_hashes_streaming(str(a))["sha256"] != compute_hashes_streaming(str(b))["sha256"]


def test_hash_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        compute_hashes_streaming(str(tmp_path / "nope"))


def test_empty_folder_is_not_verified(tmp_path):
    assert compute_hashes_streaming(str(tmp_path))["verified"] is False


def test_zip_slip_is_rejected(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../../../ESCAPED.db", b"SQLite format 3\x00" + b"\x00" * 100)
        z.writestr("data/data/com.whatsapp/databases/msgstore.db", b"SQLite format 3\x00" + b"\x00" * 100)
    ws = tmp_path / "ws" / "a" / "b"
    ws.mkdir(parents=True)
    engine = TerabyteForensicContainerEngine(str(archive), str(ws))
    engine.index_and_materialize_targets()
    assert not list(tmp_path.rglob("ESCAPED.db"))
    assert engine.rejected_entries == ["../../../ESCAPED.db"]


def test_unsupported_container_fails_loudly(tmp_path, monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    fake = tmp_path / "dump.ufd"
    fake.write_bytes(b"not a zip")
    with pytest.raises(HTTPException) as exc:
        api_server._execute_ingestion_pipeline(str(fake), "C2", "n", "e", "a")
    assert exc.value.status_code == 422




