"""X-10: an encrypted database is opened only with a key that was supplied or found in the evidence,
and a database that stays closed is said to be closed (it is never silently empty)."""
import hashlib
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server, encrypted_db, examination_report
from tests.test_phase2_module2_2_crypto import create_synthetic_sqlcipher_v4_db_and_wal


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _evidence(tmp_path, with_prefs_key=None):
    ev = tmp_path / "phone"
    ev.mkdir()
    k_enc, salt = os.urandom(32), os.urandom(16)
    create_synthetic_sqlcipher_v4_db_and_wal(ev / "signal.db", ev / "signal.db-wal", k_enc, salt)
    key_hex = (k_enc + salt).hex()
    if with_prefs_key:
        (ev / "shared_prefs").mkdir()
        (ev / "shared_prefs" / "app.xml").write_text(
            f'<map><string name="db_cipher_key">{key_hex}</string></map>', encoding="utf-8")
    return ev, key_hex


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _plog(res, stage="decrypt_database"):
    return [e for e in res["processing_log"] if e["stage"] == stage]


def test_encrypted_database_without_a_key_is_reported(client, tmp_path):
    ev, _ = _evidence(tmp_path)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "ENC-1"}).json()
    entry = _plog(res)[0]
    assert entry["file"] == "signal.db" and entry["status"] == "ENCRYPTED_NO_KEY"
    assert "no key was supplied" in entry["error"] and "not read" in entry["error"]
    state = client.get("/api/case/state").json()
    lim = examination_report.limitations(state.get("processing_log") or res["processing_log"], {})
    assert any("Encrypted, no key" in x and "signal.db" in x for x in lim)


def test_wrong_key_is_reported_the_same_way(client, tmp_path):
    ev, _ = _evidence(tmp_path)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "ENC-2",
                                                "keys": {"guess": os.urandom(48).hex(), "pw": "not the passphrase"}}).json()
    entry = _plog(res)[0]
    assert entry["status"] == "ENCRYPTED_NO_KEY" and "none authenticated" in entry["error"]


def test_supplied_key_opens_it_and_is_never_stored(client, tmp_path):
    ev, key_hex = _evidence(tmp_path)
    before = {n: _sha(ev / n) for n in ("signal.db", "signal.db-wal")}
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "ENC-3",
                                                "keys": {"signal_key": key_hex}}).json()
    entry = _plog(res)[0]
    assert entry["status"] == "OK" and "decrypted with supplied:signal_key:hex" in entry["error"]
    # the evidence file and its WAL are untouched
    assert {n: _sha(ev / n) for n in before} == before
    # the decrypted copy is a separate file that opens and holds the ten rows
    dec = [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(res["workspace_dir"], "items")) for f in fs
           if f == "signal.db" and "decrypted" in r]
    assert len(dec) == 1
    c = sqlite3.connect(f"file:{dec[0]}?mode=ro", uri=True)
    assert c.execute("SELECT count(*) FROM messages").fetchone()[0] == 10
    c.close()
    # the key is nowhere: not in the case file, not in the log, not in the audit log
    blob = b""
    for r, _, fs in os.walk(res["workspace_dir"]):
        for f in fs:
            if f.endswith((".sqlite", ".json", ".log", ".jsonl")) or f == "case_file.sqlite":
                blob += open(os.path.join(r, f), "rb").read()
    assert key_hex.encode() not in blob
    assert key_hex[:8].encode() not in str(res["processing_log"]).encode()
    audit = client.get("/api/audit").json()
    events = [e for e in audit.get("entries", audit.get("events", [])) if e.get("action") == "key_used"]
    assert events and events[0]["payload"]["fingerprint"] == encrypted_db.key_fingerprint(bytes.fromhex(key_hex))
    assert key_hex not in str(audit)


def test_key_found_in_the_evidence_is_used_and_labelled(client, tmp_path):
    ev, _ = _evidence(tmp_path, with_prefs_key=True)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "ENC-4"}).json()
    entry = _plog(res)[0]
    assert entry["status"] == "OK" and "evidence:db_cipher_key:hex" in entry["error"]


def test_damaged_pages_are_named_in_the_log(client, tmp_path):
    ev, key_hex = _evidence(tmp_path)
    raw = bytearray((ev / "signal.db").read_bytes())
    raw[4096 + 50] ^= 0xFF
    (ev / "signal.db").write_bytes(bytes(raw))
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "ENC-5", "keys": {"k": key_hex}}).json()
    entry = _plog(res)[0]
    assert entry["status"] == "WARNING" and "failed their HMAC" in entry["error"] and "not authenticated" in entry["error"]


# ---------------------------------------------------------------- helpers
def test_plain_and_non_database_files_are_not_called_encrypted(tmp_path):
    plain = tmp_path / "a.db"
    c = sqlite3.connect(plain)
    c.execute("CREATE TABLE t (x)")
    c.commit()
    c.close()
    assert encrypted_db.encrypted_database_reason(str(plain)) is None
    text = tmp_path / "b.db"
    text.write_bytes(b"hello world, this is not a database " * 100)
    assert encrypted_db.encrypted_database_reason(str(text)) is None      # low entropy
    rnd = tmp_path / "c.bin"
    rnd.write_bytes(os.urandom(4096))
    assert encrypted_db.encrypted_database_reason(str(rnd)) is None       # not a database extension
    rnd2 = tmp_path / "c.db"
    rnd2.write_bytes(os.urandom(4096))
    assert "entropy" in encrypted_db.encrypted_database_reason(str(rnd2))


def test_a_supplied_value_is_read_as_hex_base64_or_passphrase_never_invented():
    import base64
    raw = os.urandom(32)
    kinds = lambda v: [k for k, _ in encrypted_db.normalise_key(v)]          # noqa: E731
    assert "hex" in kinds(raw.hex()) and "passphrase" in kinds(raw.hex())
    assert "base64" in kinds(base64.b64encode(raw).decode())
    assert kinds("correct horse") == ["passphrase"]
    assert kinds("") == [] and kinds("ab") == []
    cands = encrypted_db.build_candidates({"a": "correct horse"}, {"noise": "Present", "empty": ""})
    assert [c[0] for c in cands] == ["supplied:a:passphrase"]


def test_evidence_passphrases_are_capped_but_supplied_keys_are_not_dropped():
    carved = {f"pref{i}": f"some preference value {i}" for i in range(80)}
    supplied = {f"mine{i}": f"my passphrase {i}" for i in range(30)}
    cands = encrypted_db.build_candidates(supplied, carved)
    assert sum(1 for c in cands if c[0].startswith("supplied:")) == 30
    assert sum(1 for c in cands if c[0].startswith("evidence:")) == encrypted_db.MAX_EVIDENCE_PASSPHRASES
