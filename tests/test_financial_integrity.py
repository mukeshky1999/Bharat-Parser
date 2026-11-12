"""Financial-layer regressions (REVIEW_FINDINGS C-08, C-12)."""
import pandas as pd

from parsers.heuristic_engine import _infer_transaction_type, synthesize_and_deduplicate_records


def _row(date, txid, cp, status, typ):
    return dict(Date=date, Transaction_ID=txid, Amount=500.0, Counterparty=cp, Status=status, Type=typ)


def test_distinct_transactions_are_not_fused():
    df = pd.DataFrame([
        _row("2024-01-15 10:30:00", "412345678901", "Ramesh Kumar", "SUCCESS", "DEBIT"),
        _row("2024-01-15 10:40:00", "T2401151040001234567", "suresh@ybl", "FAILED", "DEBIT"),
    ])
    out = synthesize_and_deduplicate_records(df)
    assert len(out) == 2
    by_id = {r.Transaction_ID: r for r in out.itertuples()}
    assert by_id["412345678901"].Counterparty == "Ramesh Kumar"
    assert by_id["412345678901"].Status == "SUCCESS"


def test_identical_reference_id_still_merges():
    df = pd.DataFrame([
        _row("2024-01-15 10:30:00", "412345678901", "Ramesh Kumar", "SUCCESS", "DEBIT"),
        _row("2024-01-15 10:30:05", "412345678901", "ramesh@ybl", "SUCCESS", "DEBIT"),
    ])
    assert len(synthesize_and_deduplicate_records(df)) == 1


def test_no_invented_ids_or_counterparties():
    df = pd.DataFrame([_row("2024-03-02 09:00:00", "N/A", "billu.singh@oksbi", "SUCCESS", None)])
    out = synthesize_and_deduplicate_records(df)
    assert not out["Transaction_ID"].astype(str).str.startswith("UPI_REF_").any()
    assert not out["Counterparty"].astype(str).str.contains("Merchant / Bill Payment").any()
    assert out.iloc[0]["Type"] != "DEBIT"  # "bill" in a VPA must not decide direction


def test_explicit_type_beats_status_keyword():
    d = _infer_transaction_type(pd.Series(["UNPAID"]), type_series=pd.Series(["CREDIT"]))
    assert d.iloc[0] == "CREDIT"


def test_deleted_notes_do_not_become_transactions(tmp_path):
    import sqlite3
    from parsers.heuristic_engine import parse_database_artifacts

    db = tmp_path / "notes.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT, created TEXT)")
    for i in range(300):
        c.execute(
            "INSERT INTO notes(body, created) VALUES (?, '2024-01-15 10:00:00')",
            (f"bhai kal tak Rs 5000 bhej dena ramesh{i}@okaxis pe, abhi nahi bheja hai",),
        )
    c.commit()
    c.execute("DELETE FROM notes")
    c.commit()
    c.close()
    arts = parse_database_artifacts(str(db), os_type="android", app_label="Notes")
    tx = arts.get("transactions")
    assert tx is None or tx.empty


def test_legacy_chat_schema_keeps_body_sender_application(tmp_path):
    from parsers.chat_social_privacy_parsers import CATEGORIZED_FORENSIC_COLUMNS
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore

    row = {c: "" for c in CATEGORIZED_FORENSIC_COLUMNS}
    row.update(Source_App="Telegram", Message_Text="hello there", Sender_ID="u123", Direction="Incoming",
               Source_File="cache4.db", Source_Table="messages", Row_ID="5001")
    store = CaseUIPaginatorStore(str(tmp_path), db_name="c.db")
    store.ingest_dataframe_chunked("chats", pd.DataFrame([row]))
    conn = store._get_connection()
    r = conn.execute("SELECT Application, Message_Body, Sender_Identifier, Forensic_Provenance FROM chats").fetchone()
    conn.close()
    assert (r["Application"], r["Message_Body"], r["Sender_Identifier"]) == ("Telegram", "hello there", "u123")
    assert "RowID=5001" in r["Forensic_Provenance"]


def test_timestamps_offset_and_dayfirst():
    from parsers.enterprise_1tb_chat_and_container_engine import format_timestamp_triplet as f

    _, utc, ist = f("2024-01-15T10:30:00+05:30")
    assert utc.startswith("2024-01-15 05:00:00") and ist.startswith("2024-01-15 10:30:00")
    assert f("05/01/2024 10:30:00")[1].startswith("2024-01-05")
    assert f("13/01/2024 10:30:00")[1].startswith("2024-01-13")


def test_reconciliation_needs_more_than_amount():
    from parsers.multi_source_fusion import reconcile_bank_statement_with_device as rec

    phone = pd.DataFrame([dict(Transaction_ID="N/A", Amount=500.0, Application="PhonePe", Type="DEBIT",
                               Date="2024-01-01 10:00:00")])
    bank = pd.DataFrame([
        dict(Date="2024-03-10 10:00:00", Ref_UTR="N/A", Debit=500.0, Credit=0.0, Narration="x"),
        dict(Date="2024-01-01 12:00:00", Ref_UTR="N/A", Debit=500.0, Credit=0.0, Narration="y"),
        dict(Date="2024-01-01 12:05:00", Ref_UTR="N/A", Debit=500.0, Credit=0.0, Narration="z"),
    ])
    out = rec(bank, phone)
    assert list(out["Reconciliation_Status"]) == ["NOT_FOUND_ON_PHONE", "PROBABLE_AMOUNT_DATE", "NOT_FOUND_ON_PHONE"]
