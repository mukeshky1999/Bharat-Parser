"""Review step 6: keep-out checks hold after tags are set aside, masking is not order dependent, the package is all or nothing."""
import hashlib
import os

import pandas as pd
import pytest

from parsers import case_tag_report
from parsers.review_package import INCLUDE, PackageItem, PackageRefused, build_package
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from tests.test_tag_outputs import _facts, _ids, store  # noqa: F401  (fixture)


def _conn(store):
    return store._get_connection()


def test_privileged_tag_set_aside_still_flags_its_file(store):
    c = _ids(store, "chats")
    store.tag_records("privileged", [("chats", c[1])])
    store.delete_evidence_item("EV-001")                       # the tag is detached and its record is gone
    conn = _conn(store)
    try:
        hit = case_tag_report.files_with_keep_out_records(conn, ["/x/chat.db", "other.db"])
    finally:
        conn.close()
    assert hit == {"/x/chat.db": {"privileged": 1}}


def test_wal_companion_counts_as_its_database_and_names_must_match_whole(store):
    c = _ids(store, "chats")
    store.tag_records("excluded", [("chats", c[0])])
    conn = _conn(store)
    try:
        hit = case_tag_report.files_with_keep_out_records(conn, ["chat.db-wal", "hat.db", "a.db"])
    finally:
        conn.close()
    assert list(hit) == ["chat.db-wal"]                       # "hat.db" is a substring of "chat.db" but a different file


def test_complainant_tag_set_aside_still_keeps_the_account_out(store):
    t = _ids(store, "transactions")
    store.tag_records("of_interest", [("transactions", t[1])])      # z@ybl
    store.tag_records("complainant", [("transactions", t[3])])      # z@ybl again, other record
    store.delete_evidence_item("EV-001")                            # both tags set aside
    store.ingest_dataframe_chunked("transactions", pd.DataFrame({
        "Transaction_ID": ["T2", "T4"], "Amount": [20.0, 70.0], "Counterparty": ["Zed", "Zed Again"], "VPA": ["z@ybl", "z@ybl"],
        "Account": [None, None], "Application": ["PhonePe"] * 2,
        "Forensic_Provenance": ["pay.db :: t :: Row=2", "pay.db :: t :: Row=4"]}), evidence_item="EV-001")
    store.reattach_tags("EV-001")                                    # of_interest and complainant are placed again
    # now set aside once more and leave the records unplaced: the complainant location must still block z@ybl
    conn = _conn(store)
    try:
        conn.execute("UPDATE tags SET Record_Id = NULL, Detached = 1 WHERE Tag = 'complainant'")
        conn.commit()
        data = case_tag_report.accounts_of_interest(conn)
    finally:
        conn.close()
    assert [a["vpa"] for a in data["accounts"]] == []
    assert [a["vpa"] for a in data["left_out"]] == ["z@ybl"]


def test_untraceable_keep_out_tag_is_reported(store):
    t = _ids(store, "transactions")
    store.tag_records("of_interest", [("transactions", t[0])])
    store.tag_records("complainant", [("transactions", t[2])])
    conn = _conn(store)
    try:
        conn.execute("UPDATE tags SET Record_Id = NULL, Detached = 1, Provenance = 'gone.db :: t :: Row=9' WHERE Tag = 'complainant'")
        conn.commit()
        data = case_tag_report.accounts_of_interest(conn)
    finally:
        conn.close()
    assert data["keep_out_tags_not_traced"] == 1 and "by hand" in data["note"]


def test_privileged_set_aside_tag_withholds_a_relied_upon_record_at_the_same_place(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[1])])
    store.tag_records("privileged", [("chats", c[1])])
    conn = _conn(store)
    try:
        conn.execute("UPDATE tags SET Record_Id = NULL, Detached = 1 WHERE Tag = 'privileged'")
        conn.commit()
        facts = case_tag_report.tag_facts(conn)
    finally:
        conn.close()
    assert facts["relied_upon"] == [] and facts["relied_upon_withheld_privileged"] == 1


def test_accounts_query_handles_many_tagged_records(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="big.db")
    n = 1500
    s.ingest_dataframe_chunked("transactions", pd.DataFrame({
        "Transaction_ID": [f"T{i}" for i in range(n)], "Amount": [1.0] * n, "Counterparty": ["x"] * n,
        "VPA": [f"v{i}@ybl" for i in range(n)], "Account": [None] * n, "Application": ["PhonePe"] * n,
        "Forensic_Provenance": [f"p.db :: t :: Row={i}" for i in range(n)]}), evidence_item="EV-001")
    s.tag_records("of_interest", [("transactions", i) for i in _ids(s, "transactions")])
    conn = s._get_connection()
    try:
        assert len(case_tag_report.accounts_of_interest(conn)["accounts"]) == n
    finally:
        conn.close()


# ---------------------------------------------------------------- package
def _file(tmp_path, name, data=b"payload"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_masking_does_not_depend_on_term_order(tmp_path):
    f = _file(tmp_path, "Ramesh Kumar notes.txt")
    out = tmp_path / "pkg"
    res = build_package("C1", [PackageItem(f, INCLUDE, note="seen with Ramesh Kumar and Ram")], str(out),
                        mask_terms=["Ram", "Ramesh Kumar"])
    text = open(res.viewer_path, encoding="utf-8").read() + open(res.manifest_path, encoding="utf-8").read()
    assert "esh Kumar" not in text and "Ramesh" not in text
    assert "[REDACTED_02]" in text


def test_short_masking_terms_are_refused(tmp_path):
    f = _file(tmp_path, "a.txt")
    with pytest.raises(PackageRefused):
        build_package("C1", [PackageItem(f, INCLUDE)], str(tmp_path / "pkg"), mask_terms=["01"])
    assert not (tmp_path / "pkg").exists()


def test_failed_build_leaves_nothing_behind(tmp_path, monkeypatch):
    f1 = _file(tmp_path, "one.txt")
    f2 = _file(tmp_path, "two.txt")
    from parsers import review_package
    real = review_package.shutil.copyfile
    calls = {"n": 0}

    def flaky(src, dst, *a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real(src, dst, *a, **k)

    monkeypatch.setattr(review_package.shutil, "copyfile", flaky)
    with pytest.raises(OSError):
        build_package("C1", [PackageItem(f1, INCLUDE), PackageItem(f2, INCLUDE)], str(tmp_path / "pkg"))
    assert [p for p in os.listdir(tmp_path) if p.startswith("pkg")] == []


def test_copy_that_differs_from_the_hashed_file_is_refused(tmp_path, monkeypatch):
    f = _file(tmp_path, "one.txt")
    from parsers import review_package
    real = review_package.shutil.copyfile

    def corrupt(src, dst, *a, **k):
        real(src, dst, *a, **k)
        with open(dst, "ab") as fh:
            fh.write(b"X")

    monkeypatch.setattr(review_package.shutil, "copyfile", corrupt)
    with pytest.raises(PackageRefused):
        build_package("C1", [PackageItem(f, INCLUDE)], str(tmp_path / "pkg"))
    assert [p for p in os.listdir(tmp_path) if p.startswith("pkg")] == []
