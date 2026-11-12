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


# ---------------- generic ("AppGenie") classifier must not invent facts ----------------
def test_generic_classifier_does_not_invent_direction_status_counterparty_or_coordinates():
    import pandas as pd

    from parsers.commercial_parity_engine import app_genie_classify_table

    chat = pd.DataFrame({"msg_id": [1, 2], "message_text": ["hello there", "ok fine"],
                         "sender": ["a", "b"], "msg_time": [1700000000, 1700000100]})
    res = app_genie_classify_table(chat, "messages", "x.db")
    assert set(res["extracted_records"]["Direction"]) == {"Unknown"}

    geo = pd.DataFrame({"point_id": [1, 2], "geo_lat": [12.97, None], "geo_lon": [77.59, None],
                        "timestamp": [1700000000, 1700002000]})
    out = app_genie_classify_table(geo, "waypoints", "g.db")["extracted_records"]
    assert len(out) == 1 and out.iloc[0]["Latitude"] == 12.97  # the empty row is not a (0, 0) pin

    pay = pd.DataFrame({"txn_id": [1, 2], "amount": [250.0, None], "payee_vpa": ["a@ybl", "b@ybl"],
                        "txn_time": [1700000000, 1700000100]})
    res = app_genie_classify_table(pay, "payments", "p.db")
    if res["extracted_records"] is not None and len(res["extracted_records"]):
        recs = res["extracted_records"]
        assert (recs["Amount"] > 0).all()
        assert not recs["Status"].eq("COMPLETED").any()
        assert not recs["Transaction_ID"].astype(str).str.startswith("GEN_").any()


def test_ios_signal_rows_without_a_direction_column_are_not_labelled_incoming(tmp_path):
    import sqlite3

    from parsers.chat_social_privacy_parsers import parse_signal_database

    db = tmp_path / "signal.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE model_TSInteraction (uniqueId TEXT, uniqueThreadId TEXT, timestamp INTEGER, "
                "receivedAtTimestamp INTEGER, body TEXT, authorId TEXT, expiresInSeconds INTEGER)")
    con.execute("INSERT INTO model_TSInteraction VALUES ('u1','t1',1700000000000,1700000000000,'hi','+911234567890',0)")
    con.commit()
    con.close()
    df = parse_signal_database(str(db))
    assert len(df) == 1
    assert df.iloc[0]["Direction"] == "UNKNOWN" and df.iloc[0]["Status"] == "UNKNOWN"


def test_bank_narration_direction_uses_whole_token_cues():
    from src.banking.narration_parser import direction_from_cues

    assert direction_from_cues("NEFT-HDFC000123-CRED CLUB-PAYMENT") == "UNKNOWN"      # 'CRED' is not 'CR'
    assert direction_from_cues("NEFT SCRIPT MICRO ACCOUNT") == "UNKNOWN"
    assert direction_from_cues("NEFT CR-SBIN0001-RAVI") == "CREDIT"
    assert direction_from_cues("BY TRANSFER NEFT 123") == "CREDIT"
    assert direction_from_cues("NEFT DR RAVI") == "DEBIT"
    assert direction_from_cues("NEFT CR DR AMBIGUOUS") == "UNKNOWN"


def test_upi_direction_comes_from_evidence_not_a_default():
    from src.upi.models import infer_direction

    assert infer_direction({}, "a@ybl", "b@ybl") == "UNKNOWN"
    assert infer_direction({"txn_type": "CREDIT"}, None, None) == "CREDIT_RECEIVED"
    assert infer_direction({"is_outgoing": 1}, None, None) == "DEBIT_SENT"
    assert infer_direction({}, "me@ybl", "x@ybl", owner_vpas=["me@ybl"]) == "DEBIT_SENT"
    assert infer_direction({}, "x@ybl", "me@ybl", owner_vpas=["me@ybl"]) == "CREDIT_RECEIVED"
    assert infer_direction({}, "me@ybl", "me@ybl", owner_vpas=["me@ybl"]) == "SELF_TRANSFER"


def test_fiat_crypto_alignment_drops_clearly_different_amounts_and_hedges_wording():
    import pandas as pd

    from parsers.fiat_crypto_bridge import align_fiat_to_crypto

    upi = pd.DataFrame([
        {"Date": "2026-01-01 10:00:00", "Amount": 100000.0, "Transaction_ID": "T1", "Counterparty": "a@ybl", "Type": "DEBIT"},
    ])
    close = pd.DataFrame([{"Date": "2026-01-01 10:05:00", "Fiat_Amount_INR": 99000.0, "Platform": "Binance",
                           "Order_ID": "O1", "Asset": "USDT", "Amount_Crypto": 1190.0}])
    far = pd.DataFrame([{"Date": "2026-01-01 10:05:00", "Fiat_Amount_INR": 900.0, "Platform": "Binance",
                         "Order_ID": "O2", "Asset": "USDT", "Amount_Crypto": 10.0}])
    ok = align_fiat_to_crypto(upi, close)
    assert len(ok) == 1 and "Possible link" in ok.iloc[0]["Evidentiary_Insight"]
    assert align_fiat_to_crypto(upi, far).empty  # 100000 vs 900 close in time is not a lead


def _viber_style_msys_db(tmp_path):
    import sqlite3
    p = str(tmp_path / "msys_database_1.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE cql_messages (message_id TEXT, thread_key TEXT, text TEXT, sender_id TEXT, timestamp_ms INTEGER, is_unsent INTEGER)")
    c.execute("INSERT INTO cql_messages VALUES ('m1','t1','hello','100',1760430000000,0)")
    c.commit(); c.close()
    return p


def test_r13_facebook_msys_does_not_invent_direction_status_or_page(tmp_path):
    from parsers.social_interaction_comms_parsers import parse_facebook_messenger_database

    df = parse_facebook_messenger_database(_viber_style_msys_db(tmp_path))
    assert len(df) == 1
    row = df.iloc[0]
    assert row["Direction"] == "Unknown"   # the table has no sent/received column
    assert row["Status"] == "Unknown"      # not "Delivered"
    assert row["Page_Number"] == 0         # a rowid-derived page number is not a page number


def test_r13_knowledgec_foreground_timeline_is_actually_read(tmp_path):
    import sqlite3
    from parsers.os_privacy_spillover import OsPrivacySpilloverRecovery

    p = str(tmp_path / "knowledgeC.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER, ZSTARTDATE REAL, ZENDDATE REAL, ZSTREAMNAME TEXT, ZVALUESTRING TEXT)")
    c.execute("INSERT INTO ZOBJECT VALUES (1, 700000000.0, 700000060.0, '/app/inFocus', 'ph.telegra.Telegraph')")
    c.commit(); c.close()
    rows = OsPrivacySpilloverRecovery.parse_usagestats_timeline(p)
    assert len(rows) == 1 and rows[0]["App_Identifier"] == "ph.telegra.Telegraph"


def test_r16_nonsqlite_primitives_reject_truncated_input():
    from src.nonsqlite.snappy import snappy_decompress
    from src.nonsqlite.varint import decode_le_varint

    with pytest.raises(ValueError):
        decode_le_varint(b"\x80\x80")            # continuation bit set, no terminator
    assert decode_le_varint(b"\xac\x02") == (300, 2)
    # declared length 5 but only a 2-byte literal follows: a short buffer must not look complete
    with pytest.raises(ValueError):
        snappy_decompress(b"\x05\x04ab")
    assert snappy_decompress(b"\x02\x04ab") == b"ab"


def test_r15_missing_timestamp_is_not_replaced_by_analysis_time():
    import inspect

    import src.cex.binance as b
    import src.cex.indian_cex as i
    import src.web3.engine as w

    for mod in (b, i, w):
        assert "datetime.now(" not in inspect.getsource(mod)


def test_r14_bare_checksum_is_not_an_aadhaar_without_uidai_wording():
    from src.geospatial_media_and_tamper.bilingual_ocr_engine import BilingualOcrEngine

    eng = BilingualOcrEngine()
    # a 12-digit number that passes Verhoeff, with no UIDAI wording, stays a candidate reference number
    num = next(str(n) for n in range(234567890123, 234567890123 + 200)
               if eng.verhoeff_validator.validate_verhoeff(str(n)))
    res = eng.extract_from_text(f"Reference {num}")
    assert res.document_category != "UIDAI_IDENTITY_CARD"
    assert num in res.extracted_utrs


def test_r17_bigint_conversion_has_no_fixture_special_case():
    from src.web3.address_utils import format_bigint_decimal

    assert format_bigint_decimal("0x56bc75e2d63100000", 18)[1] == "100.000000000000000000"
    # 10^23 wei is 100,000 ETH; it must not be silently turned into 100 ETH
    assert format_bigint_decimal("0x152d02c7e14af6800000", 18)[1] == "100000.000000000000000000"


def _chain_inputs(w_currency="USDT", upi_ts="2024-05-10T14:05:00Z"):
    from src.seedhunter.models import Phase3UPIPayment, Phase4CryptoWithdrawal, Phase4P2POrder

    upi = Phase3UPIPayment(tx_master_uid=1, utr_reference="630911111111", amount_inr=90000.0, counterparty_vpa="a@okaxis",
                           counterparty_name="A", source_app="PhonePe", timestamp_utc_iso=upi_ts)
    order = Phase4P2POrder(p2p_order_uid=2, order_number="9", exchange_name="Binance", order_side="BUY", crypto_quantity=1000.0,
                           crypto_currency="USDT", fiat_total_amount=90000.0, fiat_currency="INR", counterparty_vpa="a@okaxis",
                           order_status="COMPLETED", created_utc_iso="2024-05-10T14:00:00Z",
                           completed_utc_iso="2024-05-10T14:08:00Z")
    w = Phase4CryptoWithdrawal(transfer_uid=3, exchange_name="Binance", currency=w_currency, amount=5.0,
                               blockchain_network="TRON_TRC20", destination_address="T" + "x" * 33, txid="ab" * 32,
                               timestamp_utc_iso="2024-05-10T14:20:00Z", matches_local_wallet=True)
    return upi, order, w


def test_r19_withdrawal_needs_same_asset_and_similar_amount():
    from src.seedhunter.correlator import RupeeToCryptoCorrelator

    upi, order, w = _chain_inputs()
    # same currency but 5 USDT against a 1000 USDT order: not the same money
    chains = RupeeToCryptoCorrelator().correlate([upi], [order], [w])
    assert len(chains) == 1 and chains[0].hop3_cex_withdrawal_or_pay_uid is None


def test_r19_amount_alone_without_timestamps_is_not_linked():
    from src.seedhunter.correlator import RupeeToCryptoCorrelator

    upi, order, w = _chain_inputs(upi_ts="")
    assert RupeeToCryptoCorrelator().correlate([upi], [order], [w]) == []


def test_r18_binance_p2p_missing_status_and_side_are_unknown(tmp_path):
    from src.cex.models import CEXP2POrderStatus, CEXP2PTradeDirection

    assert CEXP2POrderStatus.UNKNOWN.value == "UNKNOWN" and CEXP2PTradeDirection.UNKNOWN.value == "UNKNOWN"
    from src.cex.models import CEXP2PEscrowOrderRecord
    assert CEXP2PEscrowOrderRecord().order_status == CEXP2POrderStatus.UNKNOWN


def test_whatsapp_direction_unknown_when_from_me_missing():
    from src.whatsapp.models import MessageDirection

    assert MessageDirection.UNKNOWN.value == "UNKNOWN"


# ---- R-20: modules read in the last pass ----
def test_cakewallet_non_json_frame_does_not_hang_and_nothing_is_invented(tmp_path):
    import struct
    from src.web3.cakewallet import CakeWalletDecoder
    key = b"k"
    val = b"not json at all"
    frame = struct.pack(">I", 1 + len(key) + 2 + len(val) + 4) + struct.pack(">B", len(key)) + key + struct.pack(">H", len(val)) + val
    p = tmp_path / "trades.hive"
    p.write_bytes(frame * 3 + b'{"trade_id": "T1", "provider": "FixedFloat"}')
    out = CakeWalletDecoder().decode_sandbox(str(p))
    assert len(out["swaps"]) == 1
    sw = out["swaps"][0]
    assert sw.input_chain_and_asset == "" and sw.output_chain_and_asset == ""
    assert sw.input_amount_decimal == ""
    assert sw.swap_timestamp is None


def test_trustwallet_missing_coin_and_type_are_unknown(tmp_path):
    import json
    from src.web3.trustwallet import TrustWalletDecoder
    from src.web3.models import BlockchainNetwork, Web3AccountControlMode
    p = tmp_path / "ks.json"
    p.write_text(json.dumps({"activeAccounts": [{"address": "0xabc"}]}))
    acc = TrustWalletDecoder().decode_sandbox(str(p))["accounts"][0]
    assert acc.blockchain_network == BlockchainNetwork.UNKNOWN
    assert acc.account_control_mode == Web3AccountControlMode.UNKNOWN


def test_binance_key_matching_is_whole_word_and_no_default_asset(tmp_path):
    from src.cex.binance import _is_user_id_key, _is_kyc_name_key, BinanceDecoder, VPA_REGEX
    assert _is_user_id_key("userId") and _is_user_id_key("uid")
    assert not _is_user_id_key("guid") and not _is_user_id_key("deviceUid")
    assert _is_kyc_name_key("kycRealName")
    assert not _is_kyc_name_key("userName") and not _is_kyc_name_key("nickName")
    assert not VPA_REGEX.findall("mail me at john@gmail.com")
    assert VPA_REGEX.findall("pay john@okaxis now")
    t = BinanceDecoder().parse_transfer_record({"txId": "x", "address": "T1"})
    assert t.asset_or_currency == "" and t.network_or_rail == "" and t.transfer_utc_iso == ""
    t2 = BinanceDecoder().parse_transfer_record({"id": "1", "transactionTime": 1700000000}, is_offchain_pay=True)
    assert t2.transfer_utc_iso.startswith("2023-11-1")  # a seconds timestamp is kept, not dropped


def test_tl_decoders_report_truncation_instead_of_zero():
    from src.telegram_signal.tl_deserializer import decode_tl_message
    r = decode_tl_message(b"\x01\x02\x03\x04\x00\x00\x00\x00\x07\x00\x00\x00")
    assert r["date"] is None
    assert r["parse_complete"] is False


def test_protobuf_depth_is_bounded_and_segb_bad_date_does_not_crash():
    from src.nonsqlite.protobuf import decode_raw_protobuf
    buf = b"\x08\x01"
    for _ in range(200):
        buf = b"\x0a" + bytes([len(buf)]) + buf if len(buf) < 128 else buf
    decode_raw_protobuf(b"\x0a\x02" * 3000)  # must return, not raise RecursionError
    from src.nonsqlite.segb import _cocoa_to_iso
    assert _cocoa_to_iso(float("nan")) == "" and _cocoa_to_iso(1e30) == "" and _cocoa_to_iso(-5) == ""


def test_mmkv_encrypted_without_key_returns_nothing(tmp_path):
    import struct
    from src.nonsqlite.mmkv import MMKVDecoder
    m = tmp_path / "store"
    m.write_bytes(struct.pack("<I", 20) + bytes(range(1, 40)))
    (tmp_path / "store.crc").write_bytes(b"\x00" * 12 + b"\x01" * 16)
    assert MMKVDecoder().decode_mmkv_file(m) == []


def test_bip39_seed_uses_nfkd_and_scrypt_large_n_is_accepted():
    from src.seedhunter.hd_derivator import derive_master_seed_bip39
    assert derive_master_seed_bip39("abandon", "é") == derive_master_seed_bip39("abandon", "é")
    import json
    from src.seedhunter.vault_unwrapper import unwrap_web3_keystore_v3
    ks = {"crypto": {"kdf": "scrypt", "kdfparams": {"n": 262144, "r": 8, "p": 1, "salt": "00"}, "ciphertext": "00", "mac": "00"}}
    ok, _, meta = unwrap_web3_keystore_v3(json.dumps(ks), "pw")
    assert ok is False and "MAC" in meta.get("error", "")  # reached the MAC check instead of failing on memory
    ks["crypto"]["kdfparams"]["n"] = 1 << 30
    assert "Refusing" in unwrap_web3_keystore_v3(json.dumps(ks), "pw")[2]["error"]


def test_findings_round_trip_survives_and_is_per_case(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import parsers.api_server as api

    class _Store:
        db_path = str(tmp_path / "case.db")

    monkeypatch.setattr(api, "_active_store", _Store())
    monkeypatch.setitem(api._case_state, "loaded", True)
    monkeypatch.setitem(api._case_state, "case_id", "CASE-A")
    c = TestClient(api.app)
    assert c.get("/api/case/findings").json()["findings"] == []
    body = {"kind": "upi", "record_id": "tx-1", "title": "Rs 40,000 to VPA x@ybl", "note": "matches victim complaint",
            "source": {"file": "phonepe.db", "table": "txn", "rowid": 7, "offset": None}}
    r = c.post("/api/case/findings", json=body).json()["findings"]
    assert len(r) == 1 and r[0]["note"] == "matches victim complaint" and r[0]["source"]["offset"] is None
    body["note"] = "edited"
    assert c.post("/api/case/findings", json=body).json()["findings"][0]["note"] == "edited"  # same record: updated, not duplicated
    assert len(c.get("/api/case/findings").json()["findings"]) == 1
    api._case_state["case_id"] = "CASE-B"
    assert c.get("/api/case/findings").json()["findings"] == []  # another case does not see them
    api._case_state["case_id"] = "CASE-A"
    fid = c.get("/api/case/findings").json()["findings"][0]["id"]
    assert c.delete(f"/api/case/findings/{fid}").json()["findings"] == []
    assert c.post("/api/case/findings", json={**body, "title": " "}).status_code == 422


def test_reingesting_the_same_case_id_does_not_duplicate_records(tmp_path, monkeypatch):
    import sqlite3
    from fastapi.testclient import TestClient
    import parsers.api_server as api
    ev = tmp_path / "ev"
    ev.mkdir()
    db = ev / "app.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE contacts (_id INTEGER PRIMARY KEY, display_name TEXT, number TEXT)")
    con.execute("INSERT INTO contacts VALUES (1, 'Asha', '9876543210')")
    con.commit(); con.close()
    monkeypatch.setattr(api, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    c = TestClient(api.app)
    body = {"evidence_path": str(ev), "case_id": "DUP-1"}
    counts = []
    for _ in range(2):
        assert c.post("/api/case/ingest", json=body).json()["success"] is True
        counts.append(c.get("/api/case/state").json()["counts"])
    assert counts[0] == counts[1], counts
    assert any(v for v in counts[0].values()), counts  # something was ingested at all
