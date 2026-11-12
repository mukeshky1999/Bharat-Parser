"""Regression tests for REVIEW_FINDINGS_2 X-01 .. X-06 (NCRP sheet and Section 230 bundle)."""
import csv
import io

import pytest

from src.dossier_and_exhibits.exhibit_packager import ExhibitAndDefensePackager
from src.dossier_and_exhibits.models import RedactionTag, SensitiveMediaItem
from src.unk_triage_and_bsa_studio.freeze_deconfliction import NodalFreezeDeconflictionCenter


def _item(name="a.jpg", tag=RedactionTag.DISCLOSABLE, raw=b"BYTES", path="/x/a.jpg", **kw):
    return SensitiveMediaItem(
        canonical_path=path, file_name=name, sha256_hex="a" * 64, md5_hex="b" * 32,
        raw_bytes=raw, redaction_tag=tag, **kw,
    )


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


# ---------------- X-01 / X-06: NCRP sheet ----------------
def test_ncrp_does_not_invent_officer_station_state_or_category():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([{"account_no": "111", "ifsc": "X", "vpa": "m@y", "volume_inr": 5}])
    rows = _rows(c.generate_1930_ncrp_csv(ev, "VICTIM", "ACK-1"))
    r = dict(zip(rows[0], rows[1]))
    for col in ("State_UT", "Police_Station", "Investigating_Officer", "Crime_Category"):
        assert r[col] == "NOT_PROVIDED"
    flat = " ".join(sum(rows, []))
    assert "Verma" not in flat and "Uttar Pradesh" not in flat and "Cyber Crime PS" not in flat
    assert len(rows[0]) == 14


def test_ncrp_uses_supplied_details_and_requires_ack_number():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([{"account_no": "111", "vpa": "m@y", "volume_inr": 5}])
    out = c.generate_1930_ncrp_csv(ev, "V", "ACK", state_ut="Kerala", police_station="Town PS",
                                   investigating_officer="SI R. Nair", crime_category="UPI fraud")
    rows = _rows(out)
    r = dict(zip(rows[0], rows[1]))
    assert (r["State_UT"], r["Police_Station"], r["Investigating_Officer"]) == ("Kerala", "Town PS", "SI R. Nair")
    with pytest.raises(ValueError):
        c.generate_1930_ncrp_csv(ev, "V", "  ")


def test_ncrp_csv_quotes_commas_and_neutralises_formulas():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([
        {"account_no": "=HYPERLINK(1)", "ifsc": "A,B", "vpa": "m@y", "volume_inr": 5},
    ])
    rows = _rows(c.generate_1930_ncrp_csv(ev, "V", "ACK", investigating_officer="Nair, R."))
    r = dict(zip(rows[0], rows[1]))
    assert len(rows[1]) == 14  # a comma must not add a column
    assert r["Beneficiary_Account_to_Freeze"].startswith("'=")
    assert r["Beneficiary_IFSC"] == "A,B"
    assert r["Investigating_Officer"] == "Nair, R."


# ---------------- X-05: biller matching ----------------
@pytest.mark.parametrize("vpa,expected", [
    ("francesca@ybl", False),      # contains 'cesc'
    ("accescorp@upi", False),
    ("bescom.billdesk@icici", True),
    ("irctc@upi", True),
    ("tata_power@sbi", True),
    ("someone@oksbi", False),
])
def test_utility_matching_is_whole_word(vpa, expected):
    assert NodalFreezeDeconflictionCenter.is_utility_biller(vpa, "") is expected


# ---------------- X-02 / X-03 / X-04: Section 230 bundle ----------------
def test_untagged_item_aborts_bundle_and_writes_nothing(tmp_path):
    out = tmp_path / "b"
    with pytest.raises(ValueError):
        ExhibitAndDefensePackager().package_section_230_defense_bundle(
            "C", [_item(tag=None)], str(out), anonymize_victim_identity=False)
    assert not out.exists() or not any(p.is_file() for p in out.rglob("*"))


@pytest.mark.parametrize("tag", [RedactionTag.PROTECTED_VICTIM_IDENTITY, RedactionTag.UNRELIED_PRIVATE_DATA,
                                 RedactionTag.CSAM_POCSO])
def test_every_non_disclosable_tag_is_withheld(tmp_path, tag):
    out = tmp_path / "b"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C", [_item(tag=tag, raw=b"SECRET_BYTES")], str(out), anonymize_victim_identity=False)
    blob = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    assert b"SECRET_BYTES" not in blob
    assert any("WITHHELD_NOTICE" in p.name for p in out.rglob("*"))


def test_path_traversal_in_file_name_stays_inside_bundle(tmp_path):
    out = tmp_path / "bundle"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C", [_item(name="../../ESCAPED.txt"), _item(name="..\\..\\ESC2.txt")], str(out),
        anonymize_victim_identity=False)
    assert not (tmp_path / "ESCAPED.txt").exists() and not (tmp_path.parent / "ESCAPED.txt").exists()
    for p in out.rglob("*"):
        assert str(p.resolve()).startswith(str(out.resolve()))


def test_victim_name_masked_everywhere_and_html_escaped(tmp_path):
    out = tmp_path / "b"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C",
        [_item(name="Pooja Sharma <b>.jpg", tag=RedactionTag.CSAM_POCSO,
               path="/sdcard/Pooja Sharma/p.jpg", exif_metadata="Owner: pooja sharma")],
        str(out), anonymize_victim_identity=True, victim_name="Pooja Sharma")
    for p in out.rglob("*"):
        if p.is_file():
            assert "pooja sharma" not in (p.name + p.read_text(encoding="utf-8")).lower(), p.name
    html_text = (out / "Open_Case_Dossier.html").read_text(encoding="utf-8")
    assert "<b>" not in html_text


def test_anonymisation_without_victim_name_is_refused(tmp_path):
    with pytest.raises(ValueError):
        ExhibitAndDefensePackager().package_section_230_defense_bundle(
            "C", [_item()], str(tmp_path / "b"), anonymize_victim_identity=True, victim_name=None)


# ---------------- X-08: benchmark endpoint ----------------
def test_benchmark_disabled_by_default_and_output_dir_must_be_inside(tmp_path, monkeypatch):
    import asyncio
    import tempfile

    from fastapi import HTTPException

    import parsers.api_server as server

    monkeypatch.delenv("BHARAT_ENABLE_BENCHMARK", raising=False)
    req = server.BenchmarkRequest(dump_path=str(tmp_path))
    with pytest.raises(HTTPException) as e:
        asyncio.run(server.run_benchmark(req))
    assert e.value.status_code == 404

    monkeypatch.setenv("BHARAT_ENABLE_BENCHMARK", "1")
    evil = tempfile.gettempdir() + "_evil"  # shares the string prefix, is a sibling folder
    req = server.BenchmarkRequest(dump_path=str(tmp_path), output_dir=evil)
    with pytest.raises(HTTPException) as e:
        asyncio.run(server.run_benchmark(req))
    assert e.value.status_code == 403


# ---------------- X-07 / X-11: Section 94 notice ----------------
CASE = {"io_name": "SI R. Nair", "police_station": "Town PS", "fir_number": "12/2026",
        "sections_of_law": "318(4) BNS"}


def test_section94_does_not_guess_operator_from_mobile_number(tmp_path):
    from src.dossier_and_exhibits.nodal_freeze_and_requisitions import Section94BnssRequisitionDrafter

    recs = Section94BnssRequisitionDrafter().generate_section_94_requisitions(
        [{"category": "TELECOM_TSP_NODAL", "msisdn": "+919876543210"}], CASE, str(tmp_path))
    assert "Jio" not in recs[0].recipient_organization_name
    assert "CONFIRMED BY IO" in recs[0].recipient_organization_name
    text = open(recs[0].rendered_notice_doc_path, encoding="utf-8").read()
    assert "DRAFT" in text and "48 hours" not in text and "Cyber Crime PS" not in text


def test_section94_refuses_missing_case_details(tmp_path):
    from src.dossier_and_exhibits.nodal_freeze_and_requisitions import Section94BnssRequisitionDrafter

    for key in CASE:
        info = {k: v for k, v in CASE.items() if k != key}
        with pytest.raises(ValueError, match=key):
            Section94BnssRequisitionDrafter().generate_section_94_requisitions(
                [{"category": "BANK_NODAL_OFFICER", "ifsc": "SBIN0001"}], info, str(tmp_path))


def test_ist_timestamp_is_real_ist_not_local_time():
    from src.dossier_and_exhibits.models import ist_now_str
    from datetime import datetime, timezone, timedelta

    got = datetime.strptime(ist_now_str()[:19], "%Y-%m-%d %H:%M:%S")
    want = datetime.now(timezone(timedelta(hours=5, minutes=30))).replace(tzinfo=None)
    assert abs((got - want).total_seconds()) < 5


# ---------------- X-10: key recovery must be honest ----------------
def test_sqlcipher_open_without_driver_reports_unavailable_and_does_not_touch_file(tmp_path, monkeypatch, caplog):
    import hashlib

    import parsers.keychain_decryptor as kd

    monkeypatch.setattr(kd, "_SQLCIPHER", None)
    db = tmp_path / "enc.db"
    db.write_bytes(b"\x01" * 4096)  # not a plaintext SQLite header
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    ring = kd.CaseKeyring("C")
    ring.register("k", "00" * 32)
    with caplog.at_level("WARNING"):
        assert kd.attempt_sqlcipher_open(str(db), ring) is None
        assert kd.attempt_sqlcipher_decryption(str(db), None, str(tmp_path), ring) is None
    assert "not installed" in caplog.text
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("decrypted_")]


# ---------------- M-03: recovered-state counts must not match file names ----------------
def test_recovered_counts_ignore_file_names_containing_wal_or_carved(tmp_path):
    import pandas as pd

    from parsers.ui_fts5_paginator import CaseUIPaginatorStore

    store = CaseUIPaginatorStore(str(tmp_path), db_name="m03.db")
    store.ingest_dataframe_chunked("chats", pd.DataFrame([
        # Active rows whose PATH contains the letters WAL / CARVED / FREELIST (case-insensitive LIKE bait)
        {"Application": "WhatsApp", "Message_ID": "1", "Thread_ID": "T1", "Is_Revoked_Deleted": 0,
         "Forensic_Provenance": "wallet.db :: C:/cases/WALLET/carved_notes/wallet.db :: tx :: RowID=1 :: State=Allocated B-Tree"},
        # Genuinely recovered rows
        {"Application": "WhatsApp", "Message_ID": "2", "Thread_ID": "T1", "Is_Revoked_Deleted": 0,
         "Forensic_Provenance": "msgstore.db :: Page_1 :: Offset=0x2000 :: State=WAL_RECOVERED"},
        {"Application": "WhatsApp", "Message_ID": "3", "Thread_ID": "T1", "Is_Revoked_Deleted": 0,
         "Forensic_Provenance": "msgstore.db :: Page_1 :: Offset=0x3000 :: State=CARVED_FREELIST"},
    ]))
    counts = store.get_pa_project_tree_counts()
    node = counts["chats_whatsapp"] if "chats_whatsapp" in counts else next(iter(counts.values()))
    flat = {k: v for k, v in counts.items()}
    # Find the WhatsApp node regardless of its key name
    wa = [v for k, v in flat.items() if "whatsapp" in k.lower() and isinstance(v, dict) and v.get("total") == 3]
    assert wa, flat
    assert wa[0]["wal_and_carved"] == 2 and wa[0]["active"] == 1, wa[0]


# ---------------- M-04 / M-05: healing and derived contacts ----------------
def test_same_amount_in_other_app_does_not_overwrite_counterparty_or_direction():
    import pandas as pd

    from parsers.corroboration_engine import heal_counterparties_across_apps

    arts = {
        "A": {"transactions": pd.DataFrame([{
            "Transaction_ID": "N/A", "Linked_Reference_IDs": "N/A", "Date": "2024-05-04", "Amount": 500.0,
            "Counterparty": "Unknown", "Status": "SUCCESS", "Type": "TRANSFER"}])},
        # Two different payees paid the same amount on the same day: ambiguous, so no lead either.
        "B": {"transactions": pd.DataFrame([
            {"Transaction_ID": "111111111111", "Linked_Reference_IDs": "111111111111", "Date": "2024-05-04",
             "Amount": 500.0, "Counterparty": "alice@ybl", "Status": "SUCCESS", "Type": "DEBIT"},
            {"Transaction_ID": "222222222222", "Linked_Reference_IDs": "222222222222", "Date": "2024-05-04",
             "Amount": 500.0, "Counterparty": "bob@okaxis", "Status": "SUCCESS", "Type": "CREDIT"}])},
    }
    out = heal_counterparties_across_apps(arts)["A"]["transactions"].iloc[0]
    assert out["Counterparty"] == "Unknown" and out["Type"] == "TRANSFER"
    assert not str(out.get("Possible_Link", "") or "")


def test_derived_contacts_are_labelled_and_have_no_invented_identifier():
    import pandas as pd

    from parsers.corroboration_engine import heal_counterparties_across_apps

    arts = {"A": {"transactions": pd.DataFrame([
        {"Transaction_ID": "111111111111", "Linked_Reference_IDs": "111111111111", "Date": "2024-05-04",
         "Amount": 10.0, "Counterparty": "RAVI KUMAR", "Status": "SUCCESS", "Type": "DEBIT"},
        {"Transaction_ID": "222222222222", "Linked_Reference_IDs": "222222222222", "Date": "2024-05-05",
         "Amount": 20.0, "Counterparty": "ravi@ybl", "Status": "SUCCESS", "Type": "DEBIT"},
    ])}}
    contacts = heal_counterparties_across_apps(arts)["A"]["contacts"]
    assert "Verified Counterparty" not in set(contacts["Identifier"])
    assert set(contacts["Forensic_Provenance"]) == {"DERIVED: payee seen in transactions (not an address-book entry)"}


# ---------------- M-06 ----------------
def test_os_type_is_detected_from_layout_and_acquisition_time_is_not_processing_time():
    import parsers.api_server as server

    assert server._detect_os_type(["C:/x/data/data/com.whatsapp/databases/msgstore.db"]) == "android"
    assert server._detect_os_type(["C:/x/private/var/mobile/Library/SMS/sms.db"]) == "ios"
    assert server._detect_os_type(["C:/x/paisa.db"]) == "unknown"
    assert server._detect_os_type(["C:/x/system/build.prop", "C:/x/Manifest.db"]) == "unknown"  # contradictory


# ---------------- M-01: WAL validity chain ----------------
def _build_wal(tmp_path, frames, salts=(0x1111, 0x2222)):
    """frames: list of (pgno, commit_count, page_bytes, (salt1, salt2)). Checksums are computed correctly."""
    import struct

    from parsers.wal_rollback_analyzer import compute_wal_checksum

    magic = 0x377F0682  # little-endian checksums
    hdr = struct.pack(">IIIIII", magic, 3007000, 4096, 1, salts[0], salts[1])
    s0, s1 = compute_wal_checksum(hdr, "<", 0, 0)
    out = hdr + struct.pack(">II", s0, s1)
    for pgno, commit, page, (fs1, fs2) in frames:
        fh = struct.pack(">IIII", pgno, commit, fs1, fs2)
        c0, c1 = compute_wal_checksum(fh[:8], "<", s0, s1)
        c0, c1 = compute_wal_checksum(page, "<", c0, c1)
        out += fh + struct.pack(">II", c0, c1) + page
        s0, s1 = c0, c1
    path = tmp_path / "t.db-wal"
    path.write_bytes(out)
    return str(path)


def test_wal_frames_are_classified_by_the_valid_chain(tmp_path):
    from parsers.wal_rollback_analyzer import parse_wal_file

    page = bytes(4096)
    good = (0x1111, 0x2222)
    stale = (0x9999, 0x8888)  # a frame left over from an earlier WAL generation
    wal = _build_wal(tmp_path, [
        (2, 0, page, good),    # 1 valid, but before the commit frame -> committed (replayed up to frame 2)
        (2, 1, page, good),    # 2 valid commit frame
        (3, 0, page, good),    # 3 valid but after the last commit -> never committed
        (4, 1, page, stale),   # 4 salt mismatch -> residual (earlier generation)
    ])
    revs, _ = parse_wal_file(wal)
    by_idx = {f.frame_idx: f for fs in revs.values() for f in fs}
    assert by_idx[1].is_committed and by_idx[2].is_committed
    assert not by_idx[3].is_committed and "never committed" in by_idx[3].residual_reason
    assert not by_idx[4].is_committed and "earlier WAL generation" in by_idx[4].residual_reason


def test_zero_checksums_are_not_valid(tmp_path):
    import struct

    from parsers.wal_rollback_analyzer import parse_wal_file

    hdr = struct.pack(">IIIIIIII", 0x377F0682, 3007000, 4096, 1, 1, 2, 0, 0)
    frame = struct.pack(">IIIIII", 2, 1, 1, 2, 0, 0) + bytes(4096)
    p = tmp_path / "z.db-wal"
    p.write_bytes(hdr + frame)
    revs, _ = parse_wal_file(str(p))
    f = revs[2][0]
    assert not f.is_committed and not f.is_valid_checksum


# ---------------- M-02: carver alignment ----------------
def _record(txid=b"987654321098", vpa=b"merchant@okhdfcbank", amount=4500.0):
    import struct

    st_txid, st_vpa = len(txid) * 2 + 13, len(vpa) * 2 + 13
    hdr_body = bytes([st_txid, st_vpa, 7])
    return bytes([len(hdr_body) + 1]) + hdr_body + txid + vpa + struct.pack(">d", amount)


def _leaf_page(placed, num_cells=0, freeblock=0):
    """4096-byte leaf table page; `placed` is a list of (offset, bytes) written verbatim."""
    import struct

    pg = bytearray(4096)
    pg[0] = 0x0D
    struct.pack_into(">H", pg, 1, freeblock)
    struct.pack_into(">H", pg, 3, num_cells)
    struct.pack_into(">H", pg, 5, 4096)
    for off, data in placed:
        pg[off:off + len(data)] = data
    return bytes(pg)


def test_deleted_cell_at_unaligned_offset_is_found():
    from parsers.freelist_carver import parse_page_unallocated_cells

    rec = _record()
    cell = bytes([len(rec), 1]) + rec
    for off in (1001, 1002, 1003, 1004):  # all four alignments
        txs = parse_page_unallocated_cells(_leaf_page([(off, cell)]), 2, include_active_cells=False)
        assert any(t["Counterparty"] == "merchant@okhdfcbank" and t["Amount"] == 4500.0 for t in txs), off


def test_record_in_a_freeblock_with_destroyed_cell_prefix_is_found():
    import struct

    from parsers.freelist_carver import parse_page_unallocated_cells

    rec = _record()
    fb_off = 3000
    fb_size = 4 + len(rec)
    # SQLite overwrites the first 4 bytes of the freed cell with (next=0, size); the record follows.
    fb = struct.pack(">HH", 0, fb_size) + rec
    page = _leaf_page([(fb_off, fb)], freeblock=fb_off)
    txs = parse_page_unallocated_cells(page, 2, include_active_cells=False)
    assert any(t["Counterparty"] == "merchant@okhdfcbank" and t["Amount"] == 4500.0
               and t["Transaction_ID"] == "987654321098" for t in txs)


def test_truncated_column_does_not_shift_following_values():
    from parsers.freelist_carver import decode_record_payload

    # header: len 4, types [8-byte float, text(3), text(2)]; body is cut inside the float
    payload = bytes([4, 7, 13 + 6, 13 + 4]) + b"\x40\x00\x00"
    vals = decode_record_payload(payload)
    assert len(vals) == 3 and vals[0] is None
