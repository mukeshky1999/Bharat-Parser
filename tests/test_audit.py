"""Audit log and hash manifest: tamper detection, persistence, honest labels."""
import json
from dataclasses import replace
from datetime import datetime

import pytest

from src.audit import AuditLedger, AuditTamperError, HashManifest
from src.audit.manifest import IDENTICAL, MODIFIED, NOT_REVERIFIED, UNREADABLE


def _ledger(path=None):
    lg = AuditLedger("CASE-1", path)
    lg.append("examiner", "case_open", {"evidence": "a.zip"})
    lg.append("system", "ingest", {"files": 3})
    lg.append("examiner", "pin", {"id": "r1", "note": "x"})
    return lg


def test_clean_chain_verifies_and_head_is_last_hash():
    lg = _ledger()
    res = lg.verify()
    assert res.ok and res.entries == 3 and res.head_hash == lg.entries[-1].hash


def test_editing_the_payload_breaks_the_chain():
    lg = _ledger()
    lg.entries[1] = replace(lg.entries[1], payload_json='{"files":4}')
    res = lg.verify()
    assert not res.ok and "entry 2" in res.error


def test_editing_the_actor_breaks_the_chain():
    lg = _ledger()
    lg.entries[0] = replace(lg.entries[0], actor="someone else")
    assert not lg.verify().ok


def test_deleting_a_middle_entry_is_detected():
    lg = _ledger()
    del lg.entries[1]
    res = lg.verify()
    assert not res.ok


def test_tail_removal_is_detected_only_with_a_recorded_head():
    lg = _ledger()
    quoted_head = lg.head_hash
    lg.entries.pop()                       # tail removed: chain is still internally consistent
    assert lg.verify().ok
    res = lg.verify_against_head(quoted_head)
    assert not res.ok and "not in this log" in res.error


def test_persisted_log_reloads_and_continues(tmp_path):
    p = str(tmp_path / "case" / "audit.jsonl")
    lg = _ledger(p)
    head = lg.head_hash
    again = AuditLedger("CASE-1", p)
    assert again.head_hash == head and len(again.entries) == 3
    again.append("examiner", "export", {"kind": "report"})
    assert AuditLedger("CASE-1", p).verify().ok


def test_tampered_file_refuses_to_load(tmp_path):
    p = tmp_path / "audit.jsonl"
    _ledger(str(p))
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["payload_json"] = '{"files":99}'
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditTamperError):
        AuditLedger("CASE-1", str(p))


def test_log_for_a_different_case_does_not_verify(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    _ledger(p)
    with pytest.raises(AuditTamperError):
        AuditLedger("OTHER-CASE", p)


def test_ist_label_is_real_ist_not_utc():
    lg = AuditLedger("C")
    # 2026-01-01 00:00:00 UTC is 05:30 IST
    ts_ns = int(datetime(2026, 1, 1, 0, 0, 0).replace(tzinfo=__import__("datetime").timezone.utc).timestamp() * 1e9)
    e = lg.append("a", "x", ts_ns=ts_ns)
    assert e.ts_utc.startswith("2026-01-01T00:00:00")
    assert e.ts_ist.startswith("2026-01-01 05:30:00 IST")


def test_zero_timestamp_is_kept_not_replaced_by_now():
    e = AuditLedger("C").append("a", "x", ts_ns=0)
    assert e.ts_ns == 0 and e.ts_utc.startswith("1970-01-01")


def test_unserialisable_payload_is_rejected_not_stringified():
    with pytest.raises(TypeError):
        AuditLedger("C").append("a", "x", {"when": datetime.now()})


def test_manifest_items_start_not_reverified_and_reverify_is_real(tmp_path):
    f = tmp_path / "e.bin"
    f.write_bytes(b"evidence")
    m = HashManifest()
    assert m.add_file("e.bin", str(f)).reverified == NOT_REVERIFIED
    assert m.reverify("e.bin", str(f)).reverified == IDENTICAL
    f.write_bytes(b"evidencX")
    assert m.reverify("e.bin", str(f)).reverified == MODIFIED
    f.unlink()
    assert m.reverify("e.bin", str(f)).reverified == UNREADABLE


def test_merkle_root_changes_with_content_and_carries_odd_node_up(tmp_path):
    import hashlib
    import struct

    def build(names):
        m = HashManifest()
        for n in names:
            p = tmp_path / n
            p.write_bytes(n.encode())
            m.add_file(n, str(p))
        return m

    def leaf(m, n):
        it = m.items[n]
        raw = b"\x00" + n.encode() + b"\x00" + bytes.fromhex(it.sha256) + bytes.fromhex(it.md5) + struct.pack(">Q", it.byte_size)
        return hashlib.sha256(raw).digest()

    m = build(["a", "b", "c"])
    ab = hashlib.sha256(b"\x01" + leaf(m, "a") + leaf(m, "b")).digest()
    expected = hashlib.sha256(b"\x01" + ab + leaf(m, "c")).hexdigest()      # c carried up, not paired with itself
    duplicated = hashlib.sha256(b"\x01" + ab + hashlib.sha256(b"\x01" + leaf(m, "c") + leaf(m, "c")).digest()).hexdigest()
    assert m.merkle_root() == expected != duplicated
    assert m.merkle_root() != build(["a", "b", "d"]).merkle_root()
    assert HashManifest().merkle_root() == "0" * 64
